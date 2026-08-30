//go:build unix

package discover_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/rebaze/rio/internal/discover"
)

// makeFifo creates dir/rel, and every directory above it, as a named pipe.
// A pipe is the cheapest portable way to produce a path that exists, matches a
// glob, and can never be read to EOF.
func makeFifo(t *testing.T, dir, rel string) string {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := syscall.Mkfifo(full, 0o644); err != nil {
		t.Fatalf("mkfifo %s: %v", rel, err)
	}
	return full
}

// makeUnreadable turns dir/rel into a directory nothing may open, and restores
// it when the test ends so t.TempDir can clean up.
func makeUnreadable(t *testing.T, dir, rel string) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not deny anything")
	}
	full := makeDir(t, dir, rel)
	if err := os.Chmod(full, 0o000); err != nil {
		t.Fatalf("chmod %s: %v", rel, err)
	}
	t.Cleanup(func() { _ = os.Chmod(full, 0o755) })
	return full
}

func TestResolveNamedPipeIsNotAnSBOM(t *testing.T) {
	base := t.TempDir()
	// A path named bom.json that is a pipe rather than a file. Returning it
	// as the match makes the reader in §5 step 1 block forever, which is
	// worse than any error: the build hangs with no output at all.
	fifo := makeFifo(t, base, "target/bom.json")

	_, err := discover.Resolve(base, "rcp-client", "target/**/bom.json")
	if err == nil {
		t.Fatal("Resolve succeeded, want a no-match error")
	}

	var nm *discover.NoMatchError
	if !errors.As(err, &nm) {
		t.Fatalf("Resolve error is %T, want *discover.NoMatchError", err)
	}
	if len(nm.Irregular) != 1 || nm.Irregular[0].Path != fifo {
		t.Fatalf("NoMatchError.Irregular = %v, want just %q", nm.Irregular, fifo)
	}

	// §10: the message has to name the path and say what it found there.
	msg := err.Error()
	if !strings.Contains(msg, fifo) {
		t.Errorf("no-match message does not name the pipe %q:\n%s", fifo, msg)
	}
	if !strings.Contains(msg, "named pipe") {
		t.Errorf("no-match message does not say what the path is:\n%s", msg)
	}
}

func TestResolveNamedPipeDoesNotShadowTheFile(t *testing.T) {
	base := t.TempDir()
	makeFifo(t, base, "target/products/bom.json")
	want := writeFile(t, base, "target/classes/bom.json")

	got, err := discover.Resolve(base, "rcp-client", "target/**/bom.json")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != want {
		t.Errorf("Resolve = %q, want %q", got, want)
	}
}

func TestResolveIrregularMatchesAreSorted(t *testing.T) {
	base := t.TempDir()
	// Same names as TestResolveSeveralMatchesAreSorted: readdir order and
	// lexical order of the full paths differ, so the sort is observable (§7).
	for _, rel := range []string{"target/aZ/bom.json", "target/a.b/bom.json", "target/a/bom.json", "target/a-c/bom.json"} {
		makeFifo(t, base, rel)
	}

	var nm *discover.NoMatchError
	_, err := discover.Resolve(base, "rcp-client", "target/**/bom.json")
	if !errors.As(err, &nm) {
		t.Fatalf("Resolve error is %T, want *discover.NoMatchError", err)
	}

	want := []string{
		filepath.Join(base, "target", "a-c", "bom.json"),
		filepath.Join(base, "target", "a.b", "bom.json"),
		filepath.Join(base, "target", "a", "bom.json"),
		filepath.Join(base, "target", "aZ", "bom.json"),
	}
	if len(nm.Irregular) != len(want) {
		t.Fatalf("Irregular = %v, want %d entries", nm.Irregular, len(want))
	}
	for i := range want {
		if nm.Irregular[i].Path != want[i] {
			t.Fatalf("Irregular = %v, want %v", nm.Irregular, want)
		}
	}
}

func TestResolveDanglingSymlinksAreSorted(t *testing.T) {
	base := t.TempDir()
	// A symlink to nothing matches the glob but cannot be stat'ed, so it ends
	// up in the unreadable list, which is part of the message like the rest.
	for _, rel := range []string{"target/aZ/bom.json", "target/a.b/bom.json", "target/a/bom.json", "target/a-c/bom.json"} {
		full := filepath.Join(base, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.Symlink(filepath.Join(base, "never-built"), full); err != nil {
			t.Fatalf("symlink %s: %v", rel, err)
		}
	}

	var nm *discover.NoMatchError
	_, err := discover.Resolve(base, "rcp-client", "target/**/bom.json")
	if !errors.As(err, &nm) {
		t.Fatalf("Resolve error is %T, want *discover.NoMatchError", err)
	}

	want := []string{
		filepath.Join(base, "target", "a-c", "bom.json"),
		filepath.Join(base, "target", "a.b", "bom.json"),
		filepath.Join(base, "target", "a", "bom.json"),
		filepath.Join(base, "target", "aZ", "bom.json"),
	}
	if len(nm.Unreadable) != len(want) {
		t.Fatalf("Unreadable = %v, want %d entries", nm.Unreadable, len(want))
	}
	for i := range want {
		if nm.Unreadable[i] != want[i] {
			t.Fatalf("Unreadable = %v, want %v", nm.Unreadable, want)
		}
	}
}

func TestResolveSymlinkedBuildDirectoryIsNotASecondMatch(t *testing.T) {
	base := t.TempDir()
	real := writeFile(t, base, "target/real/bom.json")
	// One SBOM, two ways to reach it. Reporting it twice would fail the run
	// for an ambiguity that does not exist, so the two are collapsed on the
	// path they resolve to.
	if err := os.Symlink(filepath.Join(base, "target", "real"), filepath.Join(base, "target", "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	got, err := discover.Resolve(base, "rcp-client", "target/**/bom.json")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Either route names the same file. The lexically first match wins, which
	// is what makes the answer the same on every run and every platform (§7),
	// and it keeps the path inside the tree the manifest pointed at even when
	// the link leads out of it.
	link := filepath.Join(base, "target", "link", "bom.json")
	if got != link {
		t.Errorf("Resolve = %q, want %q", got, link)
	}
	assertSameFile(t, got, real)
}

// assertSameFile compares two paths by what they resolve to, so a test is not
// tripped by the platform's own links: on macOS t.TempDir() hands back a path
// under /var, which is itself a symlink to /private/var.
func assertSameFile(t *testing.T, got, want string) {
	t.Helper()

	gotReal, err := filepath.EvalSymlinks(got)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", got, err)
	}
	wantReal, err := filepath.EvalSymlinks(want)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", want, err)
	}
	if gotReal != wantReal {
		t.Fatalf("Resolve = %q, which resolves to %q; want %q", got, gotReal, wantReal)
	}
}

// The counterpart to the test above: `**` must descend THROUGH a symlinked
// directory, or an SBOM that is really there is invisible — and invisible only
// when the meta character sits above the link, so the answer would flip on
// where the glob happened to be written.
func TestResolveDescendsThroughASymlinkedDirectory(t *testing.T) {
	base := t.TempDir()
	want := writeFile(t, base, "real/linux/gtk/bom.json")
	if err := os.MkdirAll(filepath.Join(base, "target"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "target", "products")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	for _, pattern := range []string{"target/**/bom.json", "target/products/**/bom.json"} {
		t.Run(pattern, func(t *testing.T) {
			got, err := discover.Resolve(base, "rcp-client", pattern)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			assertSameFile(t, got, want)
		})
	}
}

func TestResolveUnreadableSiblingDoesNotAbortAnUnambiguousMatch(t *testing.T) {
	base := t.TempDir()
	want := writeFile(t, base, "target/classes/bom.json")
	makeUnreadable(t, base, "target/secret")

	// The glob already resolved to exactly one file. A directory rio may not
	// open, that is not this artifact's SBOM, is not a reason to abort the
	// whole run: exit 2 is for the manifest's own problems (§10).
	got, err := discover.Resolve(base, "rcp-client", "target/**/bom.json")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != want {
		t.Errorf("Resolve = %q, want %q", got, want)
	}
}

func TestResolveUnreadableDirectoryIsReportedWhenNothingMatched(t *testing.T) {
	base := t.TempDir()
	secret := makeUnreadable(t, base, "target/secret")

	// With no match to return, the unreadable directory could be where the
	// SBOM is. Saying "matched no file" and stopping there would send the
	// reader looking for a build that may well have run.
	var pe *discover.PatternError
	_, err := discover.Resolve(base, "rcp-client", "target/**/bom.json")
	if !errors.As(err, &pe) {
		t.Fatalf("Resolve error is %T, want *discover.PatternError", err)
	}

	msg := pe.Error()
	// §10: every path in the message is one the reader can paste into a
	// shell, not the "secret" that doublestar reports relative to its DirFS.
	if !strings.Contains(msg, secret) {
		t.Errorf("message does not name %q absolutely:\n%s", secret, msg)
	}
	if !strings.Contains(msg, filepath.Join(base, "target")) {
		t.Errorf("message does not name the directory searched:\n%s", msg)
	}
	if !strings.Contains(msg, `"rcp-client"`) {
		t.Errorf("message does not name the artifact:\n%s", msg)
	}
}
