// Package consensus fuzzes the protobuf decoders behind the consensus
// storage: the per-epoch Point (producer statistics, cumulative weight) and
// the ElectionData (the elected producer set for a round). These records are
// read back from disk on every node start and on every reorg across an epoch
// boundary; a decoder that panics on a corrupted page refuses to start the
// node, and one that is non-canonical lets two encodings of one point disagree
// on weight.
package consensus

import (
	"testing"

	"github.com/zenon-network/go-zenon/consensus/storage"
)

func FuzzPointUnmarshal(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		var p storage.Point
		if err := p.Unmarshal(data); err != nil {
			return
		}
		// A decoded point must re-marshal; TotalWeight and per-pillar weights
		// are big.Int built from arbitrary bytes, so this checks nothing in
		// the marshal path trips on the reconstructed value.
		if _, err := p.Marshal(); err != nil {
			t.Fatalf("re-marshal of a decoded point failed: %v", err)
		}
	})
}

func FuzzElectionDataUnmarshal(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		var d storage.ElectionData
		if err := d.Unmarshal(data); err != nil {
			return
		}
		if _, err := d.Marshal(); err != nil {
			t.Fatalf("re-marshal of decoded election data failed: %v", err)
		}
	})
}
