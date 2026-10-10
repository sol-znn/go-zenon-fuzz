package remote

import (
	"os"
	"path/filepath"
	"testing"
)

// seedFromDir loads ../corpus/<name> into the fuzz seed set (shared helper,
// same as the other packages). Missing directory is not an error.
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
		if data, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
			f.Add(data)
		}
	}
}
