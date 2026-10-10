package remote

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/zenon-network/go-zenon/common/types"

	g "github.com/zenon-network/go-zenon/chain/genesis/mock"
)

// FuzzRPCDispatch is the *dispatch-level* RPC fuzzer. Its sibling
// FuzzRPCRequest mutates the whole request string as one blob, so the byte
// mutator rarely keeps the JSON envelope valid AND a real method name AND
// enough well-typed leading arguments all at once — it mostly exercises the
// envelope parser (parseMessage / isBatch) and bounces off methodNotFound.
//
// This target instead pins a syntactically valid envelope and a REAL,
// registered method name, and fuzzes only the positional-argument vector,
// which is composed structure-aware from a type-biased dictionary. So every
// input is guaranteed to reach, inside the real server:
//
//	readBatch --> parseMessage --> handleCall --> reg.callback(method)
//	          --> parsePositionalArguments(params, callb.argTypes)
//	              -> reflect.New(argType) + dec.Decode per argument
//	                 (runs every custom UnmarshalJSON / UnmarshalText on the
//	                  method's real parameter types: Address, Hash, ZTS,
//	                  *AccountBlock, GetRequiredParam, big.Int, ...)
//	          --> runMethod(real handler)(parsed adversarial values)
//
// parsePositionalArguments and callback.argTypes are unexported, so the only
// faithful way to drive them is through the production ServeCodec, exactly as a
// socket client would — the same fidelity rule the RPC envelope target follows.
//
// A panic or a hang anywhere on that path is a finding (a remotely-triggerable
// RPC DoS reachable by any client on the port); a JSON-RPC error response is
// the correct, safe outcome. Runs -parallel=1: the mock node and the
// process-global clock are shared (the runner enforces it for remote/).
func FuzzRPCDispatch(f *testing.F) {
	srv := rpcServer(f)

	// Seeds: a spread of methods at correct arity, so the mutator starts already
	// inside the argument decoders and the handlers, then mutates from there.
	// sel picks the method; pick drives per-argument value kinds and the arity
	// delta; blob supplies the raw leaf bytes (address/hash/number/data content).
	f.Add(uint16(0), uint64(0), []byte("seed"))
	f.Add(uint16(3), uint64(0x0123456789abcdef), []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77})
	f.Add(uint16(9), uint64(0xffffffffffffffff), []byte("z1qzal6c5s9rjnnxd2z7dvdhjxpmmj4fmw56a0mz"))
	f.Add(uint16(13), uint64(2), []byte(strings.Repeat("\x00", 40)))
	f.Add(uint16(1), uint64(0x9e3779b97f4a7c15), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, sel uint16, pick uint64, blob []byte) {
		if len(blob) > 1<<15 {
			return
		}
		m := dispatchMethods[int(sel)%len(dispatchMethods)]
		req := `{"jsonrpc":"2.0","id":1,"method":"` + m.name + `","params":` + buildParams(m, pick, blob) + `}`
		guard(t, "RPC dispatch "+m.name, func() { serveOne(srv, []byte(req)) })
	})
}

// rpcMethod is a real, registered public JSON-RPC method and the positional
// arity its Go handler declares. The registered name is the namespace from
// rpc/apis.go joined to the handler method with a lowercased first letter (the
// server's formatName convention): Ledger.GetFrontierMomentum becomes
// "ledger.getFrontierMomentum".
type rpcMethod struct {
	name  string
	arity int
}

// dispatchMethods is the public surface any client on the RPC port can call.
// stats.networkInfo is deliberately omitted: its handler dereferences the p2p
// server, which is nil in this in-process harness, so a crash there is a
// harness artifact and not a node bug. Every other public method is included;
// the names and arities are taken from rpc/api and rpc/api/embedded on the
// pinned node checkout.
var dispatchMethods = []rpcMethod{
	// ledger
	{"ledger.getFrontierMomentum", 0},
	{"ledger.getMomentumBeforeTime", 1},
	{"ledger.getMomentumByHash", 1},
	{"ledger.getMomentumsByHeight", 2},
	{"ledger.getMomentumsByPage", 2},
	{"ledger.getDetailedMomentumsByHeight", 2},
	{"ledger.getAccountBlockByHash", 1},
	{"ledger.getAccountBlocksByHeight", 3},
	{"ledger.getAccountBlocksByPage", 3},
	{"ledger.getAccountInfoByAddress", 1},
	{"ledger.getFrontierAccountBlock", 1},
	{"ledger.getUnconfirmedBlocksByAddress", 3},
	{"ledger.getUnreceivedBlocksByAddress", 3},
	{"ledger.publishRawTransaction", 1}, // *AccountBlock object

	// embedded.token
	{"embedded.token.getAll", 2},
	{"embedded.token.getByOwner", 3},
	{"embedded.token.getByZts", 1},

	// embedded.sentinel
	{"embedded.sentinel.getAllActive", 2},
	{"embedded.sentinel.getByOwner", 1},
	{"embedded.sentinel.getDepositedQsr", 1},
	{"embedded.sentinel.getFrontierRewardByPage", 3},
	{"embedded.sentinel.getUncollectedReward", 1},

	// embedded.pillar
	{"embedded.pillar.checkNameAvailability", 1},
	{"embedded.pillar.getAll", 2},
	{"embedded.pillar.getByName", 1},
	{"embedded.pillar.getByOwner", 1},
	{"embedded.pillar.getDelegatedPillar", 1},
	{"embedded.pillar.getDepositedQsr", 1},
	{"embedded.pillar.getFrontierRewardByPage", 3},
	{"embedded.pillar.getPillarEpochHistory", 3},
	{"embedded.pillar.getPillarsHistoryByEpoch", 3},
	{"embedded.pillar.getQsrRegistrationCost", 0},
	{"embedded.pillar.getUncollectedReward", 1},

	// embedded.plasma
	{"embedded.plasma.get", 1},
	{"embedded.plasma.getEntriesByAddress", 3},
	{"embedded.plasma.getRequiredPoWForAccountBlock", 1}, // GetRequiredParam object

	// embedded.stake
	{"embedded.stake.getEntriesByAddress", 3},
	{"embedded.stake.getFrontierRewardByPage", 3},
	{"embedded.stake.getUncollectedReward", 1},

	// embedded.swap
	{"embedded.swap.getAssets", 0},
	{"embedded.swap.getAssetsByKeyIdHash", 1},
	{"embedded.swap.getLegacyPillars", 0},

	// embedded.spork
	{"embedded.spork.getAll", 2},

	// embedded.accelerator
	{"embedded.accelerator.getAll", 2},
	{"embedded.accelerator.getPhaseById", 1},
	{"embedded.accelerator.getPillarVotes", 2}, // (string, []Hash)
	{"embedded.accelerator.getProjectById", 1},
	{"embedded.accelerator.getVoteBreakdown", 1},

	// embedded.htlc
	{"embedded.htlc.getById", 1},
	{"embedded.htlc.getProxyUnlockStatus", 1},

	// embedded.bridge
	{"embedded.bridge.getBridgeInfo", 0},
	{"embedded.bridge.getOrchestratorInfo", 0},
	{"embedded.bridge.getSecurityInfo", 0},
	{"embedded.bridge.getTimeChallengesInfo", 0},
	{"embedded.bridge.getAllNetworks", 2},
	{"embedded.bridge.getNetworkInfo", 2},
	{"embedded.bridge.getFeeTokenPair", 1},
	{"embedded.bridge.getWrapTokenRequestById", 1},
	{"embedded.bridge.getUnwrapTokenRequestByHashAndLog", 2},
	{"embedded.bridge.getAllWrapTokenRequests", 2},
	{"embedded.bridge.getAllUnwrapTokenRequests", 2},
	{"embedded.bridge.getAllWrapTokenRequestsByToAddress", 3},
	{"embedded.bridge.getAllUnwrapTokenRequestsByToAddress", 3},
	{"embedded.bridge.getAllWrapTokenRequestsByToAddressNetworkClassAndChainId", 5},

	// embedded.liquidity
	{"embedded.liquidity.getLiquidityInfo", 0},
	{"embedded.liquidity.getSecurityInfo", 0},
	{"embedded.liquidity.getTimeChallengesInfo", 0},
	{"embedded.liquidity.getFrontierRewardByPage", 3},
	{"embedded.liquidity.getLiquidityStakeEntriesByAddress", 3},
	{"embedded.liquidity.getUncollectedReward", 1},

	// stats (p2p-free handlers only; networkInfo omitted, see above)
	{"stats.osInfo", 0},
	{"stats.processInfo", 0},
	{"stats.syncInfo", 0},
}

// buildParams renders the positional-argument array. It biases the element
// count toward the method's declared arity (so handlers actually run on parsed
// values) but sometimes over- or under-fills it to drive the "too many
// arguments" and "missing value for required argument" branches of
// parseArgumentArray. Every element is syntactically valid JSON — invalid
// envelopes are the sibling target's job — so the input is guaranteed to reach
// the per-argument decoders.
func buildParams(m rpcMethod, pick uint64, blob []byte) string {
	n := m.arity
	switch pick & 7 {
	case 5:
		n = m.arity + 1
	case 6:
		n = m.arity - 1
	case 7:
		n = m.arity + 2
	}
	if n < 0 {
		n = 0
	}
	if n > 8 {
		n = 8
	}
	pick >>= 3

	g := &argGen{blob: blob}
	elems := make([]string, 0, n)
	for i := 0; i < n; i++ {
		elems = append(elems, g.value(int(pick&15)))
		pick >>= 4
	}
	return "[" + strings.Join(elems, ",") + "]"
}

// argGen draws attacker-shaped leaf values out of the fuzz blob. It produces
// only valid JSON; the adversarial surface is the *content* fed to each
// parameter type's custom decoder and to the reflected handler.
type argGen struct {
	blob []byte
	pos  int
}

// next returns n bytes from the blob, zero-padded past the end so generation
// is total (no input is rejected at this layer).
func (g *argGen) next(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		if g.pos < len(g.blob) {
			out[i] = g.blob[g.pos]
			g.pos++
		}
	}
	return out
}

func (g *argGen) u64() uint64 { return binary.LittleEndian.Uint64(g.next(8)) }

func (g *argGen) value(kind int) string {
	switch kind {
	case 0: // a canonical address (clean decode -> handler runs)
		return jstr(sampleAddrs[int(g.next(1)[0])%len(sampleAddrs)])
	case 1: // hex text of blob bytes -> Address/Hash/ZTS UnmarshalText on attacker text
		return jstr(hex.EncodeToString(g.next(8)))
	case 2: // a well-formed 32-byte hash (clean decode -> handler runs)
		return jstr(hex.EncodeToString(g.next(32)))
	case 3: // arbitrary quoted bytes -> text parsers on non-hex junk
		return jstr(string(g.next(6)))
	case 4: // plain unsigned integer (clean decode for uint32/uint64 args)
		return strconv.FormatUint(g.u64(), 10)
	case 5: // adversarial numeric literals (overflow / negative / float / huge)
		return numLiterals[int(g.next(1)[0])%len(numLiterals)]
	case 6:
		return "null"
	case 7:
		if g.next(1)[0]&1 == 0 {
			return "false"
		}
		return "true"
	case 8: // array of hashes (accelerator.getPillarVotes []Hash + amplification)
		k := int(g.next(1)[0]) % 6
		hs := make([]string, k)
		for i := range hs {
			hs[i] = jstr(hex.EncodeToString(g.next(32)))
		}
		return "[" + strings.Join(hs, ",") + "]"
	case 9: // AccountBlock / GetRequiredParam object argument
		return g.objectArg()
	case 10: // a canonical ZTS (clean decode for ZenonTokenStandard args)
		if g.next(1)[0]&1 == 0 {
			return jstr(znnZts)
		}
		return jstr(qsrZts)
	case 11: // long string: allocation amplification through a text parser
		return jstr(strings.Repeat("a", 256+int(g.next(1)[0])*16))
	case 12: // address prefix with a wrong-length/checksum tail (UnmarshalText edge)
		return jstr("z1q" + hex.EncodeToString(g.next(int(g.next(1)[0])%30)))
	case 13: // a number delivered as a JSON string ("123")
		return jstr(strconv.FormatUint(g.u64(), 10))
	case 14: // empty object
		return "{}"
	default: // 15: empty array
		return "[]"
	}
}

// objectArg builds the two object-shaped arguments in the public surface:
// api.AccountBlock (ledger.publishRawTransaction) and GetRequiredParam
// (plasma.getRequiredPoWForAccountBlock). Fields are attacker-shaped; "data" is
// base64 because Go's encoding/json decodes a []byte field from base64.
func (g *argGen) objectArg() string {
	addr := sampleAddrs[int(g.next(1)[0])%len(sampleAddrs)]
	data := g.next(int(g.next(1)[0]))
	return fmt.Sprintf(
		`{"address":%s,"toAddress":%s,"blockType":%d,"amount":%s,"hash":%s,"data":%s,"tokenStandard":%s,"nonce":%s}`,
		jstr(addr), jstr(addr),
		g.next(1)[0],
		jstr(strconv.FormatUint(g.u64(), 10)),
		jstr(hex.EncodeToString(g.next(32))),
		jstr(encodeBase64(data)),
		jstr(znnZts),
		jstr(hex.EncodeToString(g.next(8))),
	)
}

// jstr returns s as a valid JSON string literal (handles any byte safely).
func jstr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func encodeBase64(b []byte) string {
	const tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var sb strings.Builder
	for i := 0; i < len(b); i += 3 {
		var n uint32
		var k int
		for ; k < 3 && i+k < len(b); k++ {
			n |= uint32(b[i+k]) << (16 - 8*k)
		}
		sb.WriteByte(tbl[(n>>18)&63])
		sb.WriteByte(tbl[(n>>12)&63])
		if k > 1 {
			sb.WriteByte(tbl[(n>>6)&63])
		} else {
			sb.WriteByte('=')
		}
		if k > 2 {
			sb.WriteByte(tbl[n&63])
		} else {
			sb.WriteByte('=')
		}
	}
	return sb.String()
}

// numLiterals are JSON number tokens that probe the integer/float decoders:
// unsigned max, one past it, far past it, signed bounds, negatives, floats and
// an exponent that overflows float64.
var numLiterals = []string{
	"0", "-1", "-9223372036854775808", "9223372036854775807",
	"18446744073709551615", "18446744073709551616",
	"99999999999999999999999999999999", "3.14159", "-0", "1e309", "1E-400",
}

var (
	znnZts = types.ZnnTokenStandard.String()
	qsrZts = types.QsrTokenStandard.String()

	// sampleAddrs are canonical, decodable addresses (the embedded contracts and
	// two genesis users) so an address argument can decode cleanly and let the
	// handler run, as well as be mutated into junk by the fuzzer.
	sampleAddrs = func() []string {
		addrs := []types.Address{
			types.TokenContract, types.StakeContract, types.PillarContract,
			types.PlasmaContract, types.SentinelContract, types.SwapContract,
			types.LiquidityContract, types.AcceleratorContract, types.HtlcContract,
			types.BridgeContract, types.SporkContract,
			g.User1.Address, g.User2.Address,
		}
		out := make([]string, len(addrs))
		for i, a := range addrs {
			out[i] = a.String()
		}
		return out
	}()
)
