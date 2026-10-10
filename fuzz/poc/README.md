# Proof-of-concept crashers

Runnable demonstrations of the four defects the fuzz harness found in
go-zenon `release/0.0.9`. Each builds the exact malicious input and calls the
real exported node function.

```bash
go run ./poc            # all four, each reported; exit 1 if any crashed
go run ./poc 3          # just one (1..4)
go run ./poc 1 --crash  # no recover: the process really dies (the DoS itself)
```

| # | Function | Panic | Reach | Severity |
|---|----------|-------|-------|----------|
| 1 | `nom.DeserializeAccountBlock` | nil-pointer deref (`DeProtoHash`, hash.go:87) | **local** (store read; not remote — see FINDINGS.md) | LOW |
| 2 | `nom.DeserializeMomentum` | nil-pointer deref (`DeProtoHash`, hash.go:87) | **local** (store read) | LOW |
| 3 | `db.NewPatchFromDump` | slice bounds `[-1297…:]` (patch.go:30) | **local** (patch read; uint64→int truncation) | LOW |
| 4 | `abi.NewType("")` | index out of range `[0]` (type.go:100) | **local** (only externally-supplied ABI JSON) | LOW |

All four are LOCAL-reach on release/0.0.9 — a third party cannot trigger them
remotely (the fixed-size ledger types re-canonicalize all wire/RPC input before
storage). They are robustness/availability defects, documented here in full;
the remotely-triggerable surfaces are fuzzed in `../remote` and have held up so
far. See the repo-root `FINDINGS.md` for the reach analysis and the
would-be-critical caveat (peer-to-peer snapshot sync).

## Why these matter

Findings 1–3 all share one shape: a **lenient decoder meeting a length
assumption, panicking before the caller's error handling can run**. The store
read path (`chain/account.parseAccountBlock`) is written to *return* an error
on a bad record, and the patch readers wrap the call in `DealWithErr` — both
assume a clean `error`. The panic fires first, so a single malformed or
truncated on-disk record (e.g. a partial write after an unclean shutdown)
crashes the node on read and keeps crashing on restart: a persistent,
non-self-healing denial of service against the ledger, not a recoverable error.

protobuf's leniency is what makes 1–2 realistic: a truncated record still
`Unmarshal`s successfully, leaving a field nil or short, so the corruption is
not caught at decode — it detonates one dereference later.

Finding 4 is lower severity: the node's embedded ABIs are fixed compiled-in
strings, so consensus/network input never reaches `NewType`. It is a latent
crash for any tool or future feature that parses untrusted ABI JSON.

## Remediation (upstream)

- `DeProtoHash` / `DeProtoAddress` / `BytesToZTSPanic`: return an error (or have
  the `DeProto*` block callers validate) instead of panicking on nil / wrong
  length, so the existing error branches in the store readers actually run.
- `NewType`: check `FindAllStringSubmatch` returned a non-empty result and
  return `errUnsupportedArgType(t)` otherwise, rather than indexing `[0]`.
- The patch loader bug lives in the vendored goleveldb `decodeBatch`; guard the
  decoded length against `int` truncation (`x > math.MaxInt`), or validate
  patch bytes before handing them to `Load`.
