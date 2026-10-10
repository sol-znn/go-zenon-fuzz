// Package types fuzzes the small, widely-reused parsers for the node's
// identifier types: addresses, token standards, hashes. These are called on
// RPC arguments, on config, and on JSON block bodies, and several have a
// Panic-suffixed sibling that the node uses internally. The harness pins two
// properties:
//
//   - the non-panic parser never panics for any input, and
//   - parse followed by format is stable (an accepted string round-trips),
//     because an address or ZTS that formats to something it won't re-parse is
//     a data-integrity bug.
package types

import (
	"testing"

	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common/types"
)

func FuzzParseAddress(f *testing.F) {
	f.Add("z1qxemdeddxt0kenxxxxxxxxxxxxxxxxxh9amk0")
	f.Add("z1qzal6c5s9rjnnxd2z7dvdhjxpmmj4fmw56a0mz")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		addr, err := types.ParseAddress(s)
		if err != nil {
			return
		}
		// Accepted: formatting then re-parsing must return the same address.
		round, err := types.ParseAddress(addr.String())
		if err != nil {
			t.Fatalf("address %q parsed but its String() %q did not re-parse: %v", s, addr.String(), err)
		}
		if round != addr {
			t.Fatalf("address round trip changed value: %q -> %v -> %v", s, addr, round)
		}
	})
}

func FuzzParseZTS(f *testing.F) {
	f.Add("zts1znnxxxxxxxxxxxxx9z4ulx")
	f.Add("zts1qsrxxxxxxxxxxxxxmrhjll")
	f.Fuzz(func(t *testing.T, s string) {
		zts, err := types.ParseZTS(s)
		if err != nil {
			return
		}
		round, err := types.ParseZTS(zts.String())
		if err != nil {
			t.Fatalf("zts %q parsed but its String() %q did not re-parse: %v", s, zts.String(), err)
		}
		if round != zts {
			t.Fatalf("zts round trip changed value: %q", s)
		}
	})
}

func FuzzHexToHash(f *testing.F) {
	f.Add("0000000000000000000000000000000000000000000000000000000000000000")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = types.HexToHash(s)
	})
}

// FuzzBytesToAddress targets the byte-slice constructors. BytesToAddress is a
// length-checked, error-returning form; it must stay panic-free for any
// length, in contrast to the DeProto* path that panics by design.
func FuzzBytesToAddress(f *testing.F) {
	f.Add(make([]byte, 20))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = types.BytesToAddress(b)
		_, _ = types.BytesToHash(b)
		_, _ = types.BytesToZTS(b)
	})
}

// FuzzAccountBlockJSON drives the JSON unmarshal path for an account block,
// the form the RPC layer accepts from clients. It differs from the protobuf
// path: amounts are decimal strings, the nonce is hex, and a bad nonce is the
// only hard error. A round trip is not asserted because MarshalJSON is lossy
// by design (it drops cache-only fields), so this harness only requires the
// decoder not to panic.
func FuzzAccountBlockJSON(f *testing.F) {
	f.Add(`{"version":1,"blockType":2,"amount":"100","nonce":"0000000000000000"}`)
	f.Add(`{"amount":"not-a-number","hash":"00"}`)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<16 {
			return
		}
		var ab nom.AccountBlock
		_ = ab.UnmarshalJSON([]byte(s))
	})
}
