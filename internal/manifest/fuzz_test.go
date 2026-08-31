package manifest_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/rebaze/rio/internal/manifest"
)

// FuzzLoad drives manifest parsing with arbitrary YAML.
//
// The manifest is operator input, so a broken one is expected and has to
// produce a diagnosis rather than a crash. That diagnosis is the interesting
// part: on a YAML error the loader walks the parsed node tree to rewrite the
// message with the offending field's path, and that walk runs over a document
// the parser has already rejected. Arbitrary input is exactly what exercises
// it.
func FuzzLoad(f *testing.F) {
	seed, err := os.ReadFile(filepath.Join("..", "..", "testdata", "rcp", "rio.yaml"))
	if err != nil {
		f.Fatalf("read seed manifest: %v", err)
	}
	f.Add(seed)
	f.Add([]byte(``))
	f.Add([]byte("version: 1\n"))
	f.Add([]byte("version: 1\nartifacts:\n  - id: a\n    sbom: \"*.json\"\n"))
	// A tab where YAML forbids one, and a value of the wrong type: the two
	// error shapes the rewriting path is there to explain.
	f.Add([]byte("version: 1\n\tartifacts: []\n"))
	f.Add([]byte("version: [not, a, number]\n"))
	f.Add([]byte("version: 1\ngate:\n  require: notalist\n"))

	dir := f.TempDir()
	path := filepath.Join(dir, "rio.yaml")

	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write manifest: %v", err)
		}
		m, err := manifest.Load(path)
		if err != nil {
			if m != nil {
				t.Fatalf("Load returned both a manifest and an error %v", err)
			}
			// A diagnosis with no text is not a diagnosis.
			if err.Error() == "" {
				t.Fatal("Load failed with an empty error message")
			}
			return
		}
		if m == nil {
			t.Fatal("Load returned no manifest and no error")
		}
		// index.json records this digest as the identity of the run's input,
		// so it has to be the digest of the bytes that were actually read.
		sum := sha256.Sum256(data)
		if want := hex.EncodeToString(sum[:]); m.SHA256 != want {
			t.Fatalf("SHA256 is %q, want %q", m.SHA256, want)
		}
		if m.Path != path {
			t.Fatalf("Path is %q, want the path as given, %q", m.Path, path)
		}
		if !filepath.IsAbs(m.Dir) {
			t.Fatalf("Dir is %q, want an absolute path", m.Dir)
		}
		// Globs and transform config paths resolve against Dir, so an accepted
		// manifest must never leave an artifact without an id to name it in a
		// diagnostic.
		for i, a := range m.Artifacts {
			if a.ID == "" {
				t.Fatalf("artifact %d was accepted with an empty id", i)
			}
		}
	})
}
