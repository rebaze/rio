package receipt

import (
	"os"
	"path/filepath"

	"github.com/rebaze/rio/internal/delivery"
)

// canonicalLocation resolves existing ancestors, including a symlinked source
// itself, while preserving absent reserved suffixes without creating them.
func canonicalLocation(path string) (string, error) {
	absolute, e := filepath.Abs(path)
	if e != nil {
		return "", e
	}
	current := absolute
	for {
		resolved, e := filepath.EvalSymlinks(current)
		if e == nil {
			suffix, e := filepath.Rel(current, absolute)
			if e != nil {
				return "", e
			}
			return filepath.Join(resolved, suffix), nil
		}
		if !os.IsNotExist(e) || filepath.Dir(current) == current {
			return "", e
		}
		current = filepath.Dir(current)
	}
}
func sameLocation(a, b string) bool {
	if a == b {
		return true
	}
	x, e := os.Stat(a)
	if e != nil {
		return false
	}
	y, e := os.Stat(b)
	return e == nil && os.SameFile(x, y)
}
func insideLocation(path, root string) bool {
	for current := path; ; current = filepath.Dir(current) {
		if sameLocation(current, root) {
			return true
		}
		if filepath.Dir(current) == current {
			return false
		}
	}
}

// CheckDestination rejects overlap with existing and reserved recovery state.
// Rechecking after reservation also catches case/normalization aliases through
// the now-materialized owned lock, without opening or changing a source journal.
func CheckDestination(path string, protected []string) error {
	if path == "" {
		return nil
	}
	out, e := canonicalLocation(path)
	if e != nil {
		return e
	}
	collision := func() error {
		return delivery.Fail("output_collision", "receipt destination overlaps recovery or source namespace")
	}
	for parent := filepath.Dir(out); ; parent = filepath.Dir(parent) {
		if filepath.Base(parent) == ".internal" {
			return collision()
		}
		if info, e := os.Stat(filepath.Join(parent, "00000000000000000000.json")); e == nil && info.Mode().IsRegular() {
			return collision()
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
	for _, source := range protected {
		if source == "" {
			continue
		}
		p, e := canonicalLocation(source)
		if e != nil {
			return e
		}
		for _, candidate := range []string{out, out + ".lock"} {
			for _, namespace := range []string{p, p + ".lock"} {
				if insideLocation(candidate, namespace) || insideLocation(namespace, candidate) {
					return collision()
				}
			}
		}
	}
	return nil
}
