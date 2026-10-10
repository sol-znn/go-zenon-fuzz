#!/usr/bin/env bash
# Drives every fuzz target in the module for a bounded time, regenerating the
# seed corpus first, then triaging and bucketing anything that crashes. Used
# both as the Docker image entrypoint and by hand on a dev box.
#
# The flow follows the standard loop: seed -> fuzz -> crash -> triage ->
# report. Crashers Go writes under <pkg>/testdata/fuzz/ are copied out, each
# reproducer is re-run to capture its panic, and findings are bucketed by the
# first non-runtime stack frame so the same bug reported by ten inputs is one
# entry, not ten.
#
# Env:
#   FUZZTIME    per-target budget, Go duration     (default 60s)
#   FINDINGS    where crashers + report are written (default /findings or ./findings)
#   TARGETS     space-separated "pkg:Func" overrides the auto-discovered list
#   FUZZ_RACE   if "1", run under the Go race detector (concurrency oracle).
#               Slower; most useful on the stateful chain target.
set -uo pipefail
cd "$(dirname "$0")/.."

FUZZTIME="${FUZZTIME:-60s}"
FINDINGS="${FINDINGS:-$([ -d /findings ] && echo /findings || echo ./findings)}"
RACEFLAG=""
[ "${FUZZ_RACE:-0}" = "1" ] && RACEFLAG="-race"
mkdir -p "$FINDINGS"

SUMMARY="$FINDINGS/SUMMARY.md"
NODE_DIR="../go-zenon"

# --- reproducibility metadata (triage section of the methodology) ----------
commit="$(git -C "$NODE_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
branch="$(git -C "$NODE_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
{
  echo "# Fuzzing run"
  echo
  echo "- date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- node: go-zenon @ \`$commit\` ($branch)"
  echo "- go: $(go version | awk '{print $3}')"
  echo "- fuzztime/target: $FUZZTIME${RACEFLAG:+ (race detector on)}"
  echo
  echo "| target | result | execs | corpus | coverage | bucket (top frame) |"
  echo "|---|---|---|---|---|---|"
} > "$SUMMARY"

echo ">> regenerating seed corpus"
go run ./cmd/seedgen -out ./corpus

if [ -z "${TARGETS:-}" ]; then
  TARGETS="$(grep -rEl '^func Fuzz' --include='*_test.go' . \
    | while read -r file; do
        dir="$(dirname "$file")"
        grep -oE '^func (Fuzz[A-Za-z0-9_]+)' "$file" | awk -v d="$dir" '{print d":"$2}'
      done)"
fi

# signature extracts the first stack frame inside the node (not the runtime,
# testing, or reflect machinery) from a captured panic log: the dedup key.
signature() {
  grep -E 'go-zenon/' "$1" \
    | grep -vE 'go-zenon-fuzz|/testing|/reflect' \
    | head -1 \
    | sed -E 's/\(.*//; s/^[[:space:]]+//' \
    | sed -E 's#.*/go-zenon/##'
}

# coverage turns a captured fuzz log into "execs|corpus|verdict" by reading Go's
# own progress lines ("... execs: N (M/sec), new interesting: X (total: T)").
# The trajectory of `total` interesting inputs is the coverage-saturation
# signal the exec count alone can't give: a target that HELD UP (no crash) means
# nothing if coverage was still climbing when the clock ran out — that is
# "barely explored", not "clean". Verdict:
#   saturated     - the last interval found no new coverage and the final third
#                   grew <2%: the input space around the seeds is exhausted, so
#                   "no crash" is a real result for this budget.
#   growing(+N)   - still discovering coverage at the end (N new corpus entries
#                   in the final third): extend FUZZTIME before trusting a clean.
#   n/a           - too short to print a progress line (raise FUZZTIME).
# Portable (grep/sed + shell arithmetic); no gawk-only 3-arg match(), because
# the Docker image's awk is mawk.
coverage() {
  local log="$1" execs total lastnew n mid midval tail verdict
  execs="$(grep -oE 'execs: [0-9]+' "$log" 2>/dev/null | tail -1 | grep -oE '[0-9]+$')"
  lastnew="$(grep -oE 'new interesting: [0-9]+' "$log" 2>/dev/null | tail -1 | grep -oE '[0-9]+$')"
  local series=()
  mapfile -t series < <(grep -oE 'total: [0-9]+' "$log" 2>/dev/null | grep -oE '[0-9]+$')
  n=${#series[@]}
  if [ "$n" -eq 0 ]; then
    echo "${execs:--}|-|n/a"
    return
  fi
  total="${series[$((n-1))]}"
  mid=$(( n * 2 / 3 )); [ "$mid" -lt 1 ] && mid=1
  midval="${series[$((mid-1))]}"
  tail=$(( total - midval ))
  verdict="saturated"
  if [ "${lastnew:-0}" -gt 0 ] || [ $(( tail * 50 )) -gt "$total" ]; then
    verdict="growing(+$tail)"
  fi
  echo "${execs:--}|$total|$verdict"
}

fail=0
total=0
for t in $TARGETS; do
  pkg="${t%%:*}"; fn="${t##*:}"; total=$((total+1))

  # Normalize a bare package dir ("remote") to a local import path ("./remote").
  # `go test remote` would look for a std/module import path of that name and
  # fail; auto-discovered targets already carry the ./ prefix, hand-supplied
  # TARGETS (and the Makefile's RACE_TARGETS) may not.
  case "$pkg" in ./*|/*|*.*/*) ;; *) pkg="./$pkg" ;; esac

  # The stateful chain target and the remote (ApplyBlock) target share a node /
  # process-global clock across inputs, so they must run single-worker.
  par=""
  case "$pkg" in *chain*|*remote*) par="-parallel=1" ;; esac

  echo ""
  echo ">> fuzzing $fn ($pkg) for $FUZZTIME $par $RACEFLAG"

  # Capture the run so its coverage trajectory can be parsed whether it ends
  # clean or on a crash. tee keeps it visible live; PIPESTATUS carries the real
  # test exit code past the pipe.
  runlog="$FINDINGS/$(echo "$t" | tr -c 'A-Za-z0-9' '_').fuzz.log"
  go test "$pkg" $RACEFLAG -run='^$' -fuzz="^${fn}\$" -fuzztime="$FUZZTIME" $par 2>&1 | tee "$runlog"
  rc=${PIPESTATUS[0]}

  cov="$(coverage "$runlog")"
  execs="${cov%%|*}"; rest="${cov#*|}"; corpus="${rest%%|*}"; verdict="${rest##*|}"

  if [ "$rc" -eq 0 ]; then
    echo "   coverage:   execs=$execs corpus=$corpus verdict=$verdict"
    echo "| $fn | clean | $execs | $corpus | $verdict | - |" >> "$SUMMARY"
    continue
  fi

  fail=$((fail+1))
  echo "!! $fn produced a finding"
  crashdir="$pkg/testdata/fuzz/$fn"
  bucket="unknown"
  if [ -d "$crashdir" ]; then
    dest="$FINDINGS/$fn"; mkdir -p "$dest"
    cp -f "$crashdir"/* "$dest"/ 2>/dev/null || true
    # Re-run the newest reproducer to capture its panic and bucket it.
    newest="$(ls -t "$crashdir" 2>/dev/null | head -1)"
    if [ -n "$newest" ]; then
      plog="$dest/$newest.panic.txt"
      go test "$pkg" -run="^${fn}/${newest}\$" > "$plog" 2>&1 || true
      sig="$(signature "$plog")"
      [ -n "$sig" ] && bucket="$sig"
      echo "   reproducer: $dest/$newest"
      echo "   bucket:     $bucket"
    fi
  fi
  echo "| $fn | CRASH | $execs | $corpus | $verdict | \`$bucket\` |" >> "$SUMMARY"
done

# Enrich the report with reach classification and an impact verdict: who can
# drive input to each result, and — stated first — whether anything an EXTERNAL
# party can trigger crashed (CRITICAL) versus a LOCAL-only robustness defect.
bash "$(dirname "$0")/scope.sh" "$SUMMARY" >/dev/null 2>&1 || true

echo ""
echo "============================================================"
echo "fuzzed $total target(s); $fail produced findings"
echo "report: $SUMMARY"
echo "============================================================"
cat "$SUMMARY"

[ "$fail" -eq 0 ]
