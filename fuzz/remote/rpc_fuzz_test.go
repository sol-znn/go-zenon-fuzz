package remote

import (
	"bytes"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/zenon-network/go-zenon/rpc"
	server "github.com/zenon-network/go-zenon/rpc/server"
	"github.com/zenon-network/go-zenon/zenon/mock"
)

// FuzzRPCRequest drives the full JSON-RPC server pipeline that ANY client with
// access to the RPC port reaches, on raw attacker bytes:
//
//	raw JSON --> parseMessage/isBatch --> handleBatch/handleCall
//	         --> parsePositionalArguments (reflect.New + json.Decode per arg,
//	             which runs every custom UnmarshalJSON/UnmarshalText on the
//	             method's parameter types) --> runMethod (real handler)
//
// The server is the real rpc.Server with the real public API set
// (GetPublicApis) registered against a live mock node, so dispatch executes
// genuine handler code. This is the surface where a remotely-triggerable RPC
// crash would be CRITICAL. A panic or a hang here is a finding; a JSON-RPC
// error response is the correct, safe outcome.
//
// Runs -parallel=1: the mock node and process-global clock are shared.
func FuzzRPCRequest(f *testing.F) {
	srv := rpcServer(f)

	// Seeds: a few well-formed JSON-RPC calls so the mutator starts from real
	// envelopes and real method names, then mutates the params.
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"ledger.getFrontierMomentum","params":[]}`)
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"ledger.getAccountInfoByAddress","params":["z1qzal6c5s9rjnnxd2z7dvdhjxpmmj4fmw56a0mz"]}`)
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"ledger.getAccountBlockByHash","params":["0000000000000000000000000000000000000000000000000000000000000000"]}`)
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"embedded.token.getByOwner","params":["z1qzal6c5s9rjnnxd2z7dvdhjxpmmj4fmw56a0mz",0,10]}`)
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"ledger.publishRawTransaction","params":[{"version":1,"blockType":2,"amount":"1","nonce":"0000000000000000"}]}`)
	f.Add(`[{"jsonrpc":"2.0","id":1,"method":"ledger.getFrontierMomentum","params":[]},{"jsonrpc":"2.0","id":2,"method":"stats.osInfo","params":[]}]`)

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 1<<16 {
			return
		}
		guard(t, "RPC request", func() { serveOne(srv, []byte(raw)) })
	})
}

var (
	rpcOnce sync.Once
	rpcSrv  *server.Server
)

// rpcServer builds the real public RPC server once, backed by a live mock node.
func rpcServer(tb testing.TB) *server.Server {
	rpcOnce.Do(func() {
		dir, err := os.MkdirTemp("", "zenon-rpc-fuzz-")
		if err != nil {
			tb.Fatalf("tempdir: %v", err)
		}
		z := mock.NewMockZenon(&nodeT{dir: dir})
		s := server.NewServer()
		// p2p is nil: only the stats API touches it, and only when those
		// methods are actually invoked with valid args. We register the
		// request/response modules; the "ledgerSubscribe" streaming module is
		// skipped (it needs GetSubscribeServer wiring and is a separate,
		// stateful surface).
		for _, a := range rpc.GetApis(z, nil, "ledger", "embedded", "stats") {
			if err := s.RegisterName(a.Namespace, a.Service); err != nil {
				tb.Fatalf("register %s: %v", a.Namespace, err)
			}
		}
		rpcSrv = s
	})
	return rpcSrv
}

// nodeT adapts the node's test hooks so the mock node can run under the fuzzer.
type nodeT struct{ dir string }

func (t *nodeT) Fatalf(string, ...interface{}) {}
func (t *nodeT) TempDir() string               { return t.dir }

// serveOne feeds exactly one connection's worth of bytes through the real
// server and returns when it has been processed. It uses the production codec
// (server.NewCodec, a json.Decoder over the connection), so an incomplete or
// malformed JSON stream is rejected exactly as it would be on a live socket —
// the harness must not be more permissive than the real transport, or it
// reports "hangs" that no real client can cause.
func serveOne(s *server.Server, input []byte) {
	c := &fuzzConn{r: bytes.NewReader(input)}
	s.ServeCodec(server.NewCodec(c), 0)
}

// fuzzConn is a one-shot in-memory transport: Read drains the fuzz bytes then
// returns io.EOF (the client sent this much and closed), Write is discarded.
type fuzzConn struct{ r *bytes.Reader }

func (c *fuzzConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *fuzzConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *fuzzConn) Close() error                     { return nil }
func (c *fuzzConn) SetWriteDeadline(time.Time) error { return nil }
func (c *fuzzConn) RemoteAddr() string               { return "fuzz" }
