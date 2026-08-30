// Package discover resolves an artifact's sbom glob to the single file it
// names.
//
// The manifest declares one glob per artifact and it must resolve to exactly
// one file (§2). Both failure modes abort the whole run with exit 2 before any
// output is written: zero matches is the silent failure this tool exists to
// prevent, because a run that processed nothing looks identical to a clean
// run, and several matches is the merge case, which is out of scope for v1.
//
// Globbing goes through doublestar rather than path/filepath, which has no
// `**`. Tycho writes a product SBOM under target/products/<id>/<os>/<ws>/<arch>
// and nobody is going to spell that out by hand.
package discover

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// Resolve returns the absolute path of the one file that pattern matches.
//
// pattern is interpreted relative to baseDir, the manifest's own directory. An
// absolute pattern is used as given and baseDir is not consulted. artifactID is
// carried for the errors only: every failure here names the artifact a human
// has to go and fix (§10).
//
// Directories that match are not SBOM files and are excluded. If excluding them
// leaves nothing, that is the zero-match error, reported with the directories
// listed so the near miss is visible.
func Resolve(baseDir, artifactID, pattern string) (string, error) {
	if strings.TrimSpace(pattern) == "" {
		return "", &PatternError{
			ArtifactID: artifactID,
			Pattern:    pattern,
			Reason:     "the glob is empty",
		}
	}

	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", &PatternError{
			ArtifactID: artifactID,
			Pattern:    pattern,
			Reason:     fmt.Sprintf("cannot resolve the manifest directory %q", baseDir),
			Err:        err,
		}
	}

	// doublestar patterns are forward slashed on every platform. Clean folds
	// the "./" and "../" a hand written manifest path may carry; it leaves
	// *, ?, [, ] and {} alone.
	cleaned := filepath.ToSlash(filepath.Clean(pattern))

	// Split the pattern at its first meta character and use the literal half
	// as the search root, per SplitPattern's own guidance. Joining baseDir
	// onto the pattern instead would make a repository path that happens to
	// contain *, ?, [ or { part of the glob, and there is no portable way to
	// escape it back out: on Windows the escape character is the separator.
	literal, glob := doublestar.SplitPattern(cleaned)
	if glob == "" || glob == "." || glob == ".." {
		return "", &PatternError{
			ArtifactID: artifactID,
			Pattern:    pattern,
			Reason:     "the glob names a directory, not an SBOM file",
		}
	}
	if !doublestar.ValidatePattern(glob) {
		return "", &PatternError{
			ArtifactID: artifactID,
			Pattern:    pattern,
			Reason:     "the glob is malformed",
			Err:        doublestar.ErrBadPattern,
		}
	}

	root := filepath.FromSlash(literal)
	relative := !filepath.IsAbs(root)
	if relative {
		root = filepath.Join(absBase, root)
	}
	resolved := filepath.Join(root, filepath.FromSlash(glob))

	// Report the manifest directory only when it was actually used, so an
	// absolute pattern does not get an irrelevant and misleading line.
	reportedBase := absBase
	if !relative {
		reportedBase = ""
	}

	// os.DirFS confines the walk to root, so the glob cannot wander off past
	// the literal prefix the manifest asked for. WithFailOnIOErrors turns an
	// unreadable directory into a loud failure instead of a quiet near miss;
	// doublestar does not count a non-existent path as an IO error, so a
	// pattern pointing at a tree nobody built still lands on the zero-match
	// message. WithNoFollow keeps a symlink cycle under a `**` from hanging
	// the run; a symlink in the literal prefix is still followed by the OS.
	matches, err := doublestar.Glob(os.DirFS(root), glob,
		doublestar.WithFailOnIOErrors(),
		doublestar.WithNoFollow(),
	)
	if err != nil {
		if errors.Is(err, doublestar.ErrBadPattern) {
			return "", &PatternError{
				ArtifactID: artifactID,
				Pattern:    pattern,
				Reason:     "the glob is malformed",
				Err:        err,
			}
		}
		return "", &PatternError{
			ArtifactID: artifactID,
			Pattern:    pattern,
			Reason:     fmt.Sprintf("cannot search %s", root),
			Err:        err,
		}
	}

	var files, dirs, unreadable []string
	for _, m := range matches {
		full := filepath.Join(root, filepath.FromSlash(m))
		// Stat, not Lstat: a symlink to an SBOM is an SBOM, and a symlink to a
		// directory is still a directory. That is what the OS does naturally
		// and rio adds nothing to it.
		info, err := os.Stat(full)
		switch {
		case err != nil:
			unreadable = append(unreadable, full)
		case info.IsDir():
			dirs = append(dirs, full)
		default:
			files = append(files, full)
		}
	}

	// doublestar already returns sorted results, but the error text has to be
	// byte identical across runs (§7) and that guarantee belongs here rather
	// than in a dependency's implementation detail.
	sort.Strings(files)
	sort.Strings(dirs)
	sort.Strings(unreadable)

	switch len(files) {
	case 1:
		return files[0], nil
	case 0:
		return "", &NoMatchError{
			ArtifactID:  artifactID,
			Pattern:     pattern,
			BaseDir:     reportedBase,
			Resolved:    resolved,
			Dir:         root,
			Missing:     firstMissingPath(root),
			Directories: dirs,
			Unreadable:  unreadable,
		}
	default:
		return "", &MultipleMatchesError{
			ArtifactID: artifactID,
			Pattern:    pattern,
			BaseDir:    reportedBase,
			Resolved:   resolved,
			Matches:    files,
		}
	}
}

// firstMissingPath returns the shallowest ancestor of dir, dir itself included,
// that does not exist. It returns "" when dir exists.
//
// Naming the exact component where the path stops existing is what turns
// "matched no file" from a puzzle into an instruction: nine times out of ten
// the answer is that the module was never built (§10).
func firstMissingPath(dir string) string {
	missing := ""
	for p := filepath.Clean(dir); ; {
		_, err := os.Stat(p)
		if err == nil || !errors.Is(err, fs.ErrNotExist) {
			// Anything other than "not there" is a different problem and
			// claiming the path is missing would send the reader the wrong way.
			break
		}
		missing = p
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	return missing
}
