package index_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/index"
)

func TestWrite(t *testing.T) {
	dir := t.TempDir()

	written, err := index.Write(dir, fullIndex())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	onDisk, err := os.ReadFile(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatalf("reading index.json: %v", err)
	}
	if string(onDisk) != string(written) {
		t.Errorf("Write returned bytes that differ from the file on disk")
	}

	marshalled, err := index.Marshal(fullIndex())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(onDisk) != string(marshalled) {
		t.Errorf("file on disk differs from Marshal output")
	}
	if want := readGolden(t); string(onDisk) != want {
		t.Errorf("file on disk differs from the golden")
	}
}

// TestWriteLeavesNoTempFile: the temp file lives in the destination directory
// so the rename is atomic, which means a leaked one would be visible to the
// upload script (§5 step 5).
func TestWriteLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()

	if _, err := index.Write(dir, fullIndex()); err != nil {
		t.Fatalf("Write: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 1 || names[0] != index.FileName {
		t.Errorf("directory holds %v, want only [%s]", names, index.FileName)
	}
}

func TestWriteOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, index.FileName)
	if err := os.WriteFile(path, []byte("stale\n"), 0o644); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	if _, err := index.Write(dir, fullIndex()); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if strings.Contains(string(got), "stale") {
		t.Errorf("Write did not replace the existing index")
	}
}

func TestWriteCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "target", "rio")

	if _, err := index.Write(dir, fullIndex()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, index.FileName)); err != nil {
		t.Fatalf("index.json missing: %v", err)
	}
}

// TestWriteRefusedIndexWritesNothing: an index that fails to serialize must
// leave no file at all, not a partial one.
func TestWriteRefusedIndexWritesNothing(t *testing.T) {
	dir := t.TempDir()
	idx := fullIndex()
	idx.Artifacts[0].Gate = index.Gate("")

	if _, err := index.Write(dir, idx); err == nil {
		t.Fatal("Write accepted an index with an unset gate")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("directory holds %d entries after a failed write, want 0", len(entries))
	}
}

func TestWriteDeterministic(t *testing.T) {
	first := filepath.Join(t.TempDir(), index.FileName)
	second := filepath.Join(t.TempDir(), index.FileName)

	for _, path := range []string{first, second} {
		if _, err := index.Write(filepath.Dir(path), fullIndex()); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	a, err := index.SHA256File(first)
	if err != nil {
		t.Fatalf("SHA256File: %v", err)
	}
	b, err := index.SHA256File(second)
	if err != nil {
		t.Fatalf("SHA256File: %v", err)
	}
	if a != b {
		t.Errorf("two runs produced different digests: %s vs %s", a, b)
	}
}

// The digest of "abc", the canonical SHA-256 test vector.
const sha256OfABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

func TestSHA256File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "abc.txt")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	got, err := index.SHA256File(path)
	if err != nil {
		t.Fatalf("SHA256File: %v", err)
	}
	if got != sha256OfABC {
		t.Errorf("SHA256File = %q, want %q", got, sha256OfABC)
	}
	// The equality above is the case check too, but only because this vector's
	// digest contains a-f: an all digit digest would make it vacuous, and an
	// uppercased implementation would then slip through (§4.2).
	if strings.ToUpper(got) == got {
		t.Errorf("digest must be lowercase hex containing a-f, got %q", got)
	}
}

// TestSHA256Bytes: every input.sha256 in every index rio writes comes from
// here, hashed before anything is written (§4.2), so it must agree with the
// after-writing digest byte for byte.
func TestSHA256Bytes(t *testing.T) {
	got := index.SHA256Bytes([]byte("abc"))
	if got != sha256OfABC {
		t.Errorf("SHA256Bytes = %q, want %q", got, sha256OfABC)
	}
	if strings.ToUpper(got) == got {
		t.Errorf("digest must be lowercase hex containing a-f, got %q", got)
	}

	path := filepath.Join(t.TempDir(), "abc.txt")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	onDisk, err := index.SHA256File(path)
	if err != nil {
		t.Fatalf("SHA256File: %v", err)
	}
	if got != onDisk {
		t.Errorf("SHA256Bytes = %q, SHA256File over the same bytes = %q", got, onDisk)
	}

	if empty := index.SHA256Bytes(nil); empty != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("SHA256Bytes(nil) = %q, want the empty digest", empty)
	}
}

// TestWriteNilIndexWritesNothing: Write runs at the end of a run that may
// already have failed, so a nil index must come back as an error rather than a
// panic on top of it.
func TestWriteNilIndexWritesNothing(t *testing.T) {
	dir := t.TempDir()

	data, err := index.Write(dir, nil)
	if !errors.Is(err, index.ErrNilIndex) {
		t.Fatalf("Write(dir, nil) = %v, want ErrNilIndex", err)
	}
	if data != nil {
		t.Errorf("Write returned %d bytes for a nil index, want none", len(data))
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("directory holds %d entries, want 0", len(entries))
	}
}

func TestSHA256FileEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	got, err := index.SHA256File(path)
	if err != nil {
		t.Fatalf("SHA256File: %v", err)
	}
	const wantEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != wantEmpty {
		t.Errorf("SHA256File = %q, want %q", got, wantEmpty)
	}
}

func TestSHA256FileMissing(t *testing.T) {
	_, err := index.SHA256File(filepath.Join(t.TempDir(), "nope"))
	if err == nil {
		t.Fatal("hashing a missing file must fail")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error must name the file, got %v", err)
	}
}
