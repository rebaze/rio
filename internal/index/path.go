package index

import (
	"fmt"
	"path/filepath"
	"strings"
)

// RelPath expresses target relative to base, slash separated.
//
// The index records no absolute paths: they leak the build machine's layout,
// differ between two runs of the same commit and make the digests they sit
// beside unreproducible (§7). Inputs are recorded relative to the manifest's
// directory and outputs relative to the index file's own directory (§4.2).
//
// A target outside base is refused rather than emitted as ../.., because such
// a path is only meaningful on the machine that wrote it. The caller decides
// what to do about it; silently writing it is not an option.
func RelPath(base, target string) (string, error) {
	if base == "" {
		return "", fmt.Errorf("cannot make %q relative: no base directory", target)
	}
	if target == "" {
		return "", fmt.Errorf("cannot make an empty path relative to %q", base)
	}

	// Both sides are resolved against the same working directory so a mix of
	// absolute and relative arguments still compares correctly. Symlinks are
	// deliberately not resolved: rio records the path it was given, and
	// resolving would rewrite a path the user recognises into one they do not.
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("resolving %q: %w", base, err)
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", fmt.Errorf("resolving %q: %w", target, err)
	}

	rel, err := filepath.Rel(absBase, absTarget)
	if err != nil {
		return "", fmt.Errorf("%q is outside %q: %w", target, base, err)
	}
	if rel == "." {
		return "", fmt.Errorf("%q is the directory %q itself, not a file in it", target, base)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%q is outside %q, and the index records no path that escapes its own directory", target, base)
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("%q is outside %q: no relative path exists", target, base)
	}

	// Slash separated so an index written on Windows reads the same as one
	// written on Linux (§7).
	return filepath.ToSlash(rel), nil
}
