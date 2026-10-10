package decode

import (
	"os"
	"path/filepath"
	"testing"
)

// seedFromDir loads every file under ../corpus/<name> into the fuzz seed set.
// The corpus is produced by cmd/seedgen from valid, in-protocol encodings, so
// the fuzzer starts from structurally meaningful inputs and mutates outward
// instead of spending its budget rediscovering the wire format. A missing
// directory is not an error: `go test -fuzz` still runs, just from a colder
// start.
func seedFromDir(f *testing.F, name string) {
	f.Helper()
	dir := filepath.Join("..", "corpus", name)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		f.Add(data)
	}
}
