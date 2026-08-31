package sbom

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile writes data to path via a temp file in the same directory and a
// rename, so a reader either sees the previous file or the complete new one,
// never a half written one. Same directory matters: rename is only atomic
// within one filesystem.
//
// rio never writes a partial output file (§10), and every run output goes
// through here.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("creating a temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	cleanup := func(cause error) error {
		tmp.Close()
		os.Remove(tmpName)
		return cause
	}

	if _, err := tmp.Write(data); err != nil {
		return cleanup(fmt.Errorf("writing %s: %w", path, err))
	}
	// Flushed before the rename so a crash cannot leave the rename visible
	// while the content behind it is not.
	if err := tmp.Sync(); err != nil {
		return cleanup(fmt.Errorf("flushing %s: %w", path, err))
	}
	// CreateTemp makes the file 0600. Run outputs are read by CI steps and by
	// the upload script, so they get the same mode as any other build output.
	if err := tmp.Chmod(0o644); err != nil {
		return cleanup(fmt.Errorf("setting the mode of %s: %w", path, err))
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("closing %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("renaming into %s: %w", path, err)
	}
	return nil
}
