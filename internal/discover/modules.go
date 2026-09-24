package discover

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/bmatcuk/doublestar/v4"
)

// Module records a lexical module root and its first matching marker. Both
// paths are manifest-relative and forward-slashed; neither is a glob.
type Module struct{ Root, Marker string }

// Modules selects regular marker files with a complete search. Exclusions
// apply to marker paths before deduplicating roots or checking physical aliases.
func Modules(baseDir, pattern string, exclude []string) ([]Module, error) {
	if !doublestar.ValidatePattern(pattern) {
		return nil, fmt.Errorf("malformed modules glob %q", pattern)
	}
	for _, p := range exclude {
		if !doublestar.ValidatePattern(p) {
			return nil, fmt.Errorf("malformed exclude glob %q", p)
		}
	}
	// The base is data, never part of the glob: checkout names may contain meta
	// characters. SplitPattern also avoids searching unrelated sibling trees.
	literal, glob := doublestar.SplitPattern(filepath.ToSlash(filepath.Clean(pattern)))
	root := filepath.Join(baseDir, filepath.FromSlash(literal))
	matches, err := doublestar.Glob(os.DirFS(root), glob, doublestar.WithFailOnIOErrors())
	if err != nil {
		return nil, fmt.Errorf("modules glob %q: cannot fully search %s: %w", pattern, root, err)
	}
	sort.Strings(matches)
	byRoot := map[string]Module{}
	for _, match := range matches {
		full := filepath.Join(root, filepath.FromSlash(match))
		rel, err := filepath.Rel(baseDir, full)
		if err != nil {
			return nil, err
		}
		rel = filepath.ToSlash(rel)
		excluded := false
		for _, p := range exclude {
			ok, _ := doublestar.Match(filepath.ToSlash(filepath.Clean(p)), rel)
			if ok {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		info, err := os.Stat(full)
		if err != nil {
			return nil, fmt.Errorf("marker %s: %w", rel, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		f, err := os.Open(full)
		if err != nil {
			return nil, fmt.Errorf("marker %s: %w", rel, err)
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		module := filepath.ToSlash(filepath.Dir(rel))
		if _, ok := byRoot[module]; !ok {
			byRoot[module] = Module{Root: module, Marker: rel}
		}
	}
	roots := make([]string, 0, len(byRoot))
	for r := range byRoot {
		roots = append(roots, r)
	}
	sort.Strings(roots)
	var result []Module
	var infos []os.FileInfo
	for _, r := range roots {
		info, err := os.Stat(filepath.Join(baseDir, filepath.FromSlash(r)))
		if err != nil {
			return nil, fmt.Errorf("module %s: %w", r, err)
		}
		for j, other := range infos {
			if os.SameFile(info, other) {
				return nil, fmt.Errorf("modules %q and %q refer to the same physical directory", result[j].Root, r)
			}
		}
		infos = append(infos, info)
		result = append(result, byRoot[r])
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("modules glob %q selected no module roots after exclusions", pattern)
	}
	return result, nil
}
