package sbom_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rebaze/rio/internal/sbom"
)

func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.cdx.json")

	if err := sbom.WriteFile(path, []byte("first\n")); err != nil {
		t.Fatalf("WriteFile() = %v", err)
	}
	assertFile(t, path, "first\n")

	// Overwriting an existing output is the normal case: a second run replaces
	// what the first one wrote (§4.1).
	if err := sbom.WriteFile(path, []byte("second\n")); err != nil {
		t.Fatalf("WriteFile() = %v", err)
	}
	assertFile(t, path, "second\n")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory holds %v, want only the output file: no temp debris", names)
	}
}

func TestWriteFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	if err := sbom.WriteFile(path, []byte("x")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// CreateTemp makes 0600; a build output other steps read needs 0644.
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("mode = %v, want 0644", got)
	}
}

func TestWriteFileFailsWithoutADirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "out.json")
	if err := sbom.WriteFile(path, []byte("x")); err == nil {
		t.Fatal("WriteFile() = nil, want an error naming the missing directory")
	}
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("file = %q, want %q", got, want)
	}
}
