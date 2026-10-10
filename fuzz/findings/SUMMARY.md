# Fuzzing run

- date (UTC): 2026-10-09T18:14:49Z
- node: go-zenon @ `60cf7d9bf3c464cd7ecada502c3aa364e13c85d8` (release/0.0.9)
- go: go1.27.0
- fuzztime/target: 30s

| target | result | execs | corpus | coverage | bucket (top frame) |
|---|---|---|---|---|---|
| FuzzEmbeddedUnpack | clean | 1193410 | 321 | growing(+2) | - |
| FuzzNewType | CRASH | - | - | n/a | `vm/abi.NewType` |
| FuzzABIJSON | CRASH | - | - | n/a | `vm/abi.NewType` |
| FuzzChainProgram | clean | 558 | 5 | growing(+0) | - |
| FuzzPointUnmarshal | clean | 454512 | 142 | growing(+3) | - |
| FuzzElectionDataUnmarshal | clean | 601033 | 143 | growing(+6) | - |
| FuzzAccountBlockProto | CRASH | - | - | n/a | `common/types.DeProtoHash` |
| FuzzMomentumProto | CRASH | - | - | n/a | `common/types.DeProtoHash` |
| FuzzAccountHeaderProto | CRASH | 35 | 1 | saturated | `common/types.DeProtoAddress` |
| FuzzHashHeightProto | CRASH | - | - | n/a | `unknown` |
| FuzzAccountBlockRLP | clean | 1549223 | 34 | growing(+5) | - |
| FuzzDetailedMomentumRLP | clean | 171056 | 38 | growing(+0) | - |
| FuzzHashSliceRLP | clean | 1414610 | 32 | growing(+0) | - |
| FuzzPatchDump | CRASH | - | - | n/a | `common/db.NewPatchFromDump` |
| FuzzPeerTxRaw | clean | 155736 | 15 | growing(+0) | - |
| FuzzPeerTxSigned | clean | 1752 | 21 | growing(+0) | - |
| FuzzRPCDispatch | clean | 49342 | 402 | growing(+18) | - |
| FuzzRPCRequest | clean | 34952 | 112 | growing(+35) | - |
| FuzzParseAddress | clean | 1199535 | 87 | growing(+1) | - |
| FuzzParseZTS | clean | 1313091 | 87 | growing(+1) | - |
| FuzzHexToHash | clean | 1482947 | 14 | growing(+0) | - |
| FuzzBytesToAddress | clean | 123146 | 6 | growing(+0) | - |
| FuzzAccountBlockJSON | clean | 1432448 | 453 | growing(+31) | - |
