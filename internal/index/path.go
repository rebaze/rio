package index

import (
	"fmt"
	"path/filepath"
)

// RelPath expresses target relative to base, slash separated.
//
// The index records no absolute paths: they leak the build machine's layout,
// differ between two runs of the same commit and make the digests they sit
// beside unreproducible (§7). Inputs are recorded relative to the manifest's
// directory and outputs relative to the index file's own directory (§4.2).
//
// A result that climbs out of base is still a relative path and is returned as
// one. "../ext/bom.json" is an ordinary multi-module layout, and §7 forbids
// absolute paths, not upward ones; refusing it would abort the run over a
// legal manifest. What cannot be expressed relatively at all -- a target on a
// different Windows volume -- comes back from filepath.Rel as an error, which
// is the one case §7 actually rules out.
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
		return "", fmt.Errorf("%q has no path relative to %q: %w", target, base, err)
	}
	if rel == "." {
		return "", fmt.Errorf("%q is the directory %q itself, not a file in it", target, base)
	}

	// Slash separated so an index written on Windows reads the same as one
	// written on Linux (§7).
	return filepath.ToSlash(rel), nil
}
