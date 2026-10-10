# Fuzzing run

- date (UTC): 2026-10-10T00:12:46Z
- node: go-zenon @ `60cf7d9bf3c464cd7ecada502c3aa364e13c85d8` (release/0.0.9)
- go: go1.27.0
- fuzztime/target: 15m (race detector on)

| target | result | execs | corpus | coverage | bucket (top frame) |
|---|---|---|---|---|---|
| FuzzPeerTxRaw | clean | 119085 | 107 | growing(+0) | - |
| FuzzPeerTxSigned | clean | 113347 | 57 | saturated | - |
| FuzzRPCRequest | clean | 167213 | 547 | growing(+5) | - |
| FuzzRPCDispatch | clean | 130292 | 831 | growing(+7) | - |
| FuzzChainProgram | clean | 1912 | 140 | growing(+3) | - |

<!-- scope:begin -->
## Reach & impact

Severity ranks on **reach** (model: FINDINGS.md). A crash a third party
can drive across a trust boundary is CRITICAL; one that needs on-disk
corruption or off-node tooling is LOW.

| target | reach | reachable by | result |
|---|---|---|---|
| FuzzPeerTxRaw | REMOTE | p2p peer, unauth (TxMsg->ApplyBlock, no recover) | clean |
| FuzzPeerTxSigned | REMOTE | any wallet (signed send executor) | clean |
| FuzzRPCRequest | REMOTE | any RPC client (JSON-RPC envelope) | clean |
| FuzzRPCDispatch | REMOTE | any RPC client (JSON-RPC args+dispatch) | clean |
| FuzzChainProgram | REMOTE | wallet-equivalent (full stateful program) | clean |

### Verdict

**No externally-triggerable crash this run.** All 5 of
5 REMOTE-reach surfaces held (p2p ApplyBlock, JSON-RPC
envelope + dispatch, embedded ABI unpack, RLP wire, RPC argument/JSON
parsers, stateful program). A clean here is only as strong as the
coverage verdict beside it: trust it once that column reads `saturated`,
not while it still reads `growing`.

<!-- scope:end -->
