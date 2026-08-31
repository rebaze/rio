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
// Only regular files count as matches. A directory, a named pipe, a socket or
// a device can carry the name the glob asked for and none of them is an SBOM:
// a directory cannot be read as one and a pipe blocks the reader forever, so
// step 1 of §5 ("read the file") would hang rather than fail. Such a path is
// treated as no match rather than as an error of its own, exactly as a
// directory is, so that it cannot spoil a run in which a real SBOM also
// matched. When nothing else matched it is listed in the zero-match error,
// with what it actually is, so the near miss is visible (§10).
func Resolve(baseDir, artifactID, pattern string) (string, error) {
	// TrimSpace decides only whether the pattern is usable; the pattern
	// itself is never trimmed. Silently searching "target" for a manifest
	// that said " target" would hide the typo, and searching " target"
	// literally would produce a zero-match message whose glob line looks
	// identical to a working one. Reject it instead: Error() quotes the
	// pattern, so the padding is visible in the message (§10).
	switch trimmed := strings.TrimSpace(pattern); {
	case trimmed == "":
		return "", &PatternError{
			ArtifactID: artifactID,
			Pattern:    pattern,
			Reason:     "the glob is empty",
		}
	case trimmed != pattern:
		return "", &PatternError{
			ArtifactID: artifactID,
			Pattern:    pattern,
			Reason:     "the glob has leading or trailing whitespace",
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
	// the literal prefix the manifest asked for.
	//
	// `**` descends through symlinked directories. A build that symlinks its
	// output directory still has exactly one SBOM in it, and refusing to
	// descend would hide it — and hide it only when the meta character sits
	// above the link, so the answer would flip on where the user happened to
	// put the `**`. What following costs is that one file can be reached
	// twice, by the directory and by the link; dedupeByRealPath collapses
	// that, so the run is not failed for an ambiguity that does not exist.
	//
	// Following does not risk a hang: a symlink cycle makes the kernel return
	// ELOOP, which doublestar sees as an ordinary IO error.
	//
	// IO errors are left off deliberately. doublestar's WithFailOnIOErrors
	// aborts the walk on the first unreadable directory anywhere under root,
	// which would turn a mode-0000 sibling that is not this artifact's SBOM
	// into exit 2 for the whole run. They are collected in searchError below
	// instead, and reported when the glob resolved to nothing.
	//
	// That is a deliberate trade, not a free win: an unreadable directory
	// that happens to contain a second match stays invisible, and the run
	// proceeds on the one file it could see. Failing every build with an
	// unrelated unreadable directory somewhere under the glob is the worse
	// outcome, and the common one.
	fsys := os.DirFS(root)
	matches, err := doublestar.Glob(fsys, glob)
	if err != nil {
		// Glob validates the pattern before it touches the filesystem, and
		// with IO errors ignored ErrBadPattern is the only error it can
		// return. That is why there is no separate ValidatePattern call: it
		// would say the same thing twice and leave this branch unreachable.
		return "", &PatternError{
			ArtifactID: artifactID,
			Pattern:    pattern,
			Reason:     "the glob is malformed",
			Err:        err,
		}
	}

	var files, dirs, unreadable []string
	var irregular []IrregularMatch
	for _, m := range matches {
		full := filepath.Join(root, filepath.FromSlash(m))
		// Stat, not Lstat: what matters is what the path resolves to when
		// something opens it, so a symlink to an SBOM is an SBOM and a
		// symlink to a directory is a directory. A dangling symlink fails
		// here and lands in unreadable.
		info, err := os.Stat(full)
		switch {
		case err != nil:
			unreadable = append(unreadable, full)
		case info.IsDir():
			dirs = append(dirs, full)
		case !info.Mode().IsRegular():
			irregular = append(irregular, IrregularMatch{Path: full, Kind: describeMode(info.Mode())})
		default:
			files = append(files, full)
		}
	}

	// doublestar returns matches in readdir order per directory level, which
	// is not the lexical order of the whole paths it builds from them: with
	// directories a, a-c, a.b and aZ it yields a/bom.json first, while '/'
	// sorts after '-' and '.'. The error text has to be byte identical across
	// runs and platforms (§7), so sort here.
	sort.Strings(files)
	files = dedupeByRealPath(files)
	sort.Strings(dirs)
	sort.Strings(unreadable)
	sort.Slice(irregular, func(i, j int) bool { return irregular[i].Path < irregular[j].Path })

	switch len(files) {
	case 1:
		return files[0], nil
	case 0:
		// Nothing to return, so an unreadable directory could be the reason
		// and has to be reported rather than swallowed: telling a human the
		// glob matched nothing when rio never got to look is the support call
		// §10 is written to avoid. This second walk only ever happens on a
		// path that ends the run.
		if err := searchError(fsys, glob, root); err != nil {
			return "", &PatternError{
				ArtifactID: artifactID,
				Pattern:    pattern,
				Reason:     fmt.Sprintf("cannot search %s", root),
				Err:        err,
			}
		}
		return "", &NoMatchError{
			ArtifactID:  artifactID,
			Pattern:     pattern,
			BaseDir:     reportedBase,
			Resolved:    resolved,
			Dir:         root,
			Missing:     firstMissingPath(root),
			Directories: dirs,
			Irregular:   irregular,
			Unreadable:  unreadable,
		}
	default:
		// No IO error can change this answer: more matches would still be
		// more than one, and the fix is the same either way.
		return "", &MultipleMatchesError{
			ArtifactID: artifactID,
			Pattern:    pattern,
			BaseDir:    reportedBase,
			Resolved:   resolved,
			Matches:    files,
		}
	}
}

// searchError repeats the walk with IO errors enabled and returns the first
// one doublestar hit, or nil when the search was complete.
//
// The error is re-rooted at root before it is returned. doublestar reports
// paths as os.DirFS sees them, so the raw message reads "open secret:
// permission denied" for a path the reader cannot find and cannot paste into a
// shell (§10).
func searchError(fsys fs.FS, glob, root string) error {
	_, err := doublestar.Glob(fsys, glob,
		doublestar.WithNoFollow(),
		doublestar.WithFailOnIOErrors(),
	)
	if err == nil {
		return nil
	}
	var perr *fs.PathError
	if errors.As(err, &perr) {
		// filepath.Join(root, ".") is root, so the whole-tree case ("open .:
		// not a directory", when root is not a directory at all) names root.
		rooted := *perr
		rooted.Path = filepath.Join(root, filepath.FromSlash(perr.Path))
		return &rooted
	}
	return err
}

// describeMode names what a matched path actually is, for a reader who asked
// for an SBOM and got something else. §10: the message is the whole value of
// this error, and "not a regular file" alone does not tell anyone that their
// build wrote a fifo.
func describeMode(mode fs.FileMode) string {
	switch {
	case mode&fs.ModeNamedPipe != 0:
		return "a named pipe"
	case mode&fs.ModeSocket != 0:
		return "a socket"
	case mode&fs.ModeCharDevice != 0:
		return "a character device"
	case mode&fs.ModeDevice != 0:
		return "a block device"
	default:
		return "not a regular file"
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

// dedupeByRealPath collapses matches that resolve to the same file, so one
// SBOM reachable both through a build directory and through a symlink to it
// counts once rather than failing the run as two matches.
//
// A path that cannot be resolved keeps its own identity. It is unreadable, and
// it is reported as unreadable rather than silently merged with something else.
func dedupeByRealPath(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		key, err := filepath.EvalSymlinks(p)
		if err != nil {
			key = p
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}
