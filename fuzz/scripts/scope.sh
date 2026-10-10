#!/usr/bin/env bash
# Enrich a sweep SUMMARY.md with impact scope: classify every target by REACH
# (who can drive input to it across a trust boundary) and emit a verdict that
# says, in one place, whether anything an EXTERNAL party can trigger crashed.
#
# Reach ranks severity (the model is FINDINGS.md):
#   REMOTE -> CRITICAL   a p2p peer, an RPC client or any wallet reaches it.
#   LOCAL  -> LOW        only on-disk corruption or off-node tooling reaches it.
#
# Standalone and idempotent: it reads the table fuzz.sh already wrote, appends a
# "## Reach & impact" section, and replaces that section on re-run. It never
# touches fuzz.sh, so it is safe to run against a summary a soak is still
# writing, or after the fact.
#
# Usage: scripts/scope.sh <findings-dir-or-SUMMARY.md>
set -uo pipefail

arg="${1:-./findings}"
if [ -d "$arg" ]; then SUMMARY="$arg/SUMMARY.md"; else SUMMARY="$arg"; fi
if [ ! -f "$SUMMARY" ]; then
  echo "scope: no summary at $SUMMARY" >&2
  exit 1
fi

# classify maps a target to "REACH|who can reach it". The mapping is the reach
# analysis from FINDINGS.md: the in-memory ledger types are fixed-size arrays,
# so the protobuf/patch STORAGE decoders only ever see bytes already
# round-tripped through those structs (local corruption), while the wire (RLP),
# JSON-RPC and contract-call paths take third-party bytes directly.
classify() {
  case "$1" in
    FuzzPeerTxRaw)                                   echo "REMOTE|p2p peer, unauth (TxMsg->ApplyBlock, no recover)";;
    FuzzPeerTxSigned)                                echo "REMOTE|any wallet (signed send executor)";;
    FuzzRPCRequest)                                  echo "REMOTE|any RPC client (JSON-RPC envelope)";;
    FuzzRPCDispatch)                                 echo "REMOTE|any RPC client (JSON-RPC args+dispatch)";;
    FuzzEmbeddedUnpack)                              echo "REMOTE|any wallet (embedded-contract call data)";;
    FuzzAccountBlockRLP|FuzzDetailedMomentumRLP|FuzzHashSliceRLP) echo "REMOTE|p2p peer (RLP wire decode)";;
    FuzzAccountBlockJSON)                            echo "REMOTE|any RPC client (publishRawTransaction param)";;
    FuzzParseAddress|FuzzParseZTS|FuzzHexToHash|FuzzBytesToAddress) echo "REMOTE|any RPC client (argument parser)";;
    FuzzChainProgram)                                echo "REMOTE|wallet-equivalent (full stateful program)";;
    FuzzAccountBlockProto|FuzzMomentumProto|FuzzAccountHeaderProto|FuzzHashHeightProto) echo "LOCAL|on-disk corruption only (storage read side of the re-serialization boundary)";;
    FuzzPatchDump)                                   echo "LOCAL|on-disk corruption only (stored VM-change patch loader)";;
    FuzzNewType)                                     echo "LOCAL|off-node tooling only (stock node's ABIs are fixed compile-time strings)";;
    FuzzABIJSON)                                     echo "LOCAL|off-node tooling only (operator-supplied ABI JSON)";;
    FuzzPointUnmarshal|FuzzElectionDataUnmarshal)    echo "LOCAL*|consensus protobuf, same storage boundary (reach not independently verified)";;
    *)                                               echo "?|unclassified — classify in scripts/scope.sh";;
  esac
}

trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }

# Drop any previous scope section so the script is idempotent.
tmp="$(mktemp)"
awk 'BEGIN{keep=1} /^<!-- scope:begin -->/{keep=0} keep{print} /^<!-- scope:end -->/{keep=1}' "$SUMMARY" > "$tmp"
mv "$tmp" "$SUMMARY"

# Parse the result table: "| target | result | ... | bucket |".
rows=""              # reach table body
remote_total=0; remote_clean=0
remote_crashes=""    # "fn (bucket); ..."
local_crashes=""     # "fn (bucket); ..."
while IFS= read -r line; do
  case "$line" in
    "| Fuzz"*)
      body="${line#|}"; body="${body%|}"
      IFS='|' read -r -a cols <<< "$body"
      fn="$(trim "${cols[0]}")"
      result="$(trim "${cols[1]}")"
      bucket="$(trim "${cols[${#cols[@]}-1]}")"
      bucket="${bucket//\`/}"   # the summary cell already wraps it in backticks
      [ "$bucket" = "-" ] && bucket=""
      cls="$(classify "$fn")"; reach="${cls%%|*}"; who="${cls#*|}"
      rows+="| $fn | $reach | $who | $result |"$'\n'
      case "$reach" in
        REMOTE)
          remote_total=$((remote_total+1))
          if [ "$result" = "CRASH" ]; then
            remote_crashes+="$fn${bucket:+ (\`$bucket\`)}; "
          else
            remote_clean=$((remote_clean+1))
          fi
          ;;
        LOCAL*)
          [ "$result" = "CRASH" ] && local_crashes+="$fn${bucket:+ (\`$bucket\`)}; "
          ;;
      esac
      ;;
  esac
done < "$SUMMARY"

{
  echo ""
  echo "<!-- scope:begin -->"
  echo "## Reach & impact"
  echo ""
  echo "Severity ranks on **reach** (model: FINDINGS.md). A crash a third party"
  echo "can drive across a trust boundary is CRITICAL; one that needs on-disk"
  echo "corruption or off-node tooling is LOW."
  echo ""
  echo "| target | reach | reachable by | result |"
  echo "|---|---|---|---|"
  printf '%s' "$rows"
  echo ""
  echo "### Verdict"
  echo ""
  if [ -n "$remote_crashes" ]; then
    echo "> ⚠ **CRITICAL — externally-triggerable crash.** A remote party can"
    echo "> panic the node. Treat as an unauthenticated-DoS until fixed:"
    echo ">"
    echo "> ${remote_crashes%; }"
  else
    echo "**No externally-triggerable crash this run.** All $remote_clean of"
    echo "$remote_total REMOTE-reach surfaces held (p2p ApplyBlock, JSON-RPC"
    echo "envelope + dispatch, embedded ABI unpack, RLP wire, RPC argument/JSON"
    echo "parsers, stateful program). A clean here is only as strong as the"
    echo "coverage verdict beside it: trust it once that column reads \`saturated\`,"
    echo "not while it still reads \`growing\`."
  fi
  echo ""
  if [ -n "$local_crashes" ]; then
    echo "LOCAL-class crashers (LOW — need on-disk corruption or off-node ABI"
    echo "tooling, not a remote party): ${local_crashes%; }."
    echo ""
    echo "> Caveat: the DeProto\* nil-derefs and NewPatchFromDump flip to"
    echo "> CRITICAL if peer-to-peer state-snapshot sync (zenon-fastsync /"
    echo "> Sentinel snapshots) ever writes received bytes to LevelDB *before*"
    echo "> the re-serialization step. Fix before snapshot sync ships."
  fi
  echo "<!-- scope:end -->"
} >> "$SUMMARY"

echo "scope: enriched $SUMMARY (remote: $remote_clean/$remote_total clean${remote_crashes:+, CRASHES}${local_crashes:+; local crashers present})"
