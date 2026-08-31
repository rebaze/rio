package index

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/rebaze/rio/internal/sbom"
)

// Write serializes idx and writes it to dir/index.json, returning the bytes
// that landed on disk so the caller can hash or print them without re-reading.
//
// The bytes go to a temp file in the destination directory and are renamed
// into place, so a reader either sees the previous index or the complete new
// one, never a half written file (§5 step 5). Same directory matters: rename
// is only atomic within one filesystem.
//
// index.json is written last, after every artifact, so its existence means the
// run got that far (§5 step 5). A run that fails to serialize writes nothing.
func Write(dir string, idx *Index) ([]byte, error) {
	data, err := Marshal(idx)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}

	final := filepath.Join(dir, FileName)
	if err := sbom.WriteFile(final, data); err != nil {
		return nil, err
	}
	return data, nil
}

// SHA256File returns the lowercase hex SHA-256 of a file's contents.
//
// The index records digests over the bytes on disk, computed after writing,
// not over whatever buffer the caller happened to hold (§4.2). Reading the
// file back is the point.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("hashing %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hashing %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SHA256Bytes returns the lowercase hex SHA-256 of a buffer, for the input
// digests the index records before anything is written (§4.2).
func SHA256Bytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
