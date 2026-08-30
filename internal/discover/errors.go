package discover

import (
	"fmt"
	"strings"
)

// PatternError reports a pattern rio cannot even attempt to resolve, or a
// filesystem error hit while resolving one. It is a configuration problem:
// exit 2, before anything is written (§10).
type PatternError struct {
	ArtifactID string
	// Pattern is the glob exactly as the manifest spelled it.
	Pattern string
	// Reason is the human half of the message, in lower case, no trailing dot.
	Reason string
	// Err is the underlying cause, if there was one.
	Err error
}

func (e *PatternError) Error() string {
	msg := fmt.Sprintf("artifact %q: sbom glob %q: %s", e.ArtifactID, e.Pattern, e.Reason)
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *PatternError) Unwrap() error { return e.Err }

// NoMatchError reports a glob that matched no SBOM file.
//
// §2 calls this the most dangerous silent failure in the tool, because a run
// that processed nothing looks identical to a clean run, and §10 says the
// quality of this message decides how much support it generates. So it carries
// everything a human needs to fix it without asking anyone: the artifact to go
// and look at, the glob as written, the glob as resolved, the absolute
// directory that was walked, and the reason the obvious candidates were
// rejected.
type NoMatchError struct {
	ArtifactID string
	// Pattern is the glob exactly as the manifest spelled it.
	Pattern string
	// BaseDir is the absolute manifest directory the glob was resolved
	// against. Empty when Pattern was already absolute.
	BaseDir string
	// Resolved is the absolute form of Pattern, meta characters intact.
	Resolved string
	// Dir is the absolute directory the search was rooted at: everything in
	// Resolved up to its first meta character.
	Dir string
	// Missing is the shallowest ancestor of Dir that does not exist, or empty
	// when Dir exists. This is the usual cause: the build did not run.
	Missing string
	// Directories are paths that matched but are directories, sorted.
	Directories []string
	// Unreadable are paths that matched but could not be stat'ed, sorted.
	Unreadable []string
}

func (e *NoMatchError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "artifact %q: sbom glob matched no file, want exactly 1", e.ArtifactID)
	writeLocation(&b, e.Pattern, e.BaseDir, e.Resolved)
	fmt.Fprintf(&b, "\n  searched: %s", e.Dir)

	if e.Missing != "" {
		fmt.Fprintf(&b, "\n  note:     %s does not exist", e.Missing)
	}
	writeExcluded(&b, e.Directories, "a directory, not an SBOM file")
	writeExcluded(&b, e.Unreadable, "not readable")
	return b.String()
}

// MultipleMatchesError reports a glob that matched more than one SBOM file.
//
// Every match is listed, sorted, so the human can see exactly what to narrow
// (§10). Picking one would be guessing and concatenating them would be merge,
// which is out of scope for v1 (§2).
type MultipleMatchesError struct {
	ArtifactID string
	// Pattern is the glob exactly as the manifest spelled it.
	Pattern string
	// BaseDir is the absolute manifest directory the glob was resolved
	// against. Empty when Pattern was already absolute.
	BaseDir string
	// Resolved is the absolute form of Pattern, meta characters intact.
	Resolved string
	// Matches are the absolute paths of every file that matched, sorted.
	Matches []string
}

func (e *MultipleMatchesError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "artifact %q: sbom glob matched %d files, want exactly 1", e.ArtifactID, len(e.Matches))
	writeLocation(&b, e.Pattern, e.BaseDir, e.Resolved)
	b.WriteString("\n  matches:")
	for _, m := range e.Matches {
		fmt.Fprintf(&b, "\n    %s", m)
	}
	b.WriteString("\n  narrow the glob until it names one file." +
		" Merging several SBOMs into one document is out of scope for rio v1.")
	return b.String()
}

// writeLocation renders the two lines both resolution failures share.
func writeLocation(b *strings.Builder, pattern, baseDir, resolved string) {
	fmt.Fprintf(b, "\n  glob:     %q", pattern)
	if baseDir != "" {
		fmt.Fprintf(b, " (relative to the manifest directory %s)", baseDir)
	}
	fmt.Fprintf(b, "\n  resolved: %s", resolved)
}

func writeExcluded(b *strings.Builder, paths []string, why string) {
	if len(paths) == 0 {
		return
	}
	if len(paths) == 1 {
		fmt.Fprintf(b, "\n  note:     1 path matched but is %s:", why)
	} else {
		fmt.Fprintf(b, "\n  note:     %d paths matched but each is %s:", len(paths), why)
	}
	for _, p := range paths {
		fmt.Fprintf(b, "\n    %s", p)
	}
}
