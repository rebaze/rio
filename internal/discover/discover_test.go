package discover_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/discover"
)

// writeFile creates dir/rel and every directory above it. rel is always given
// in slash form so the tests read the same on every platform.
func writeFile(t *testing.T, dir, rel string) string {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(full, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
	return full
}

func makeDir(t *testing.T, dir, rel string) string {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(full, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	return full
}

func TestResolveSingleMatch(t *testing.T) {
	base := t.TempDir()
	want := writeFile(t, base, "com.example.server/target/bom.json")
	writeFile(t, base, "com.example.client/target/bom.json")

	got, err := discover.Resolve(base, "server-war", "com.example.server/target/bom.json")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != want {
		t.Errorf("Resolve = %q, want %q", got, want)
	}
}

func TestResolveSingleMatchViaDoubleStar(t *testing.T) {
	// path/filepath.Glob cannot express this; the Tycho product output path is
	// exactly this shape, which is why doublestar is a dependency at all.
	base := t.TempDir()
	want := writeFile(t, base, "com.example.product/target/products/client/linux/gtk/x86_64/bom.json")
	writeFile(t, base, "com.example.product/target/other.json")

	got, err := discover.Resolve(base, "rcp-client", "com.example.product/target/**/bom.json")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != want {
		t.Errorf("Resolve = %q, want %q", got, want)
	}
}

func TestResolveDoubleStarMatchesZeroSegments(t *testing.T) {
	base := t.TempDir()
	want := writeFile(t, base, "target/bom.json")

	got, err := discover.Resolve(base, "rcp-client", "target/**/bom.json")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != want {
		t.Errorf("Resolve = %q, want %q", got, want)
	}
}

func TestResolveReturnsAbsolutePathForRelativeBaseDir(t *testing.T) {
	base := t.TempDir()
	writeFile(t, base, "target/bom.json")
	t.Chdir(base)

	got, err := discover.Resolve(".", "rcp-client", "target/bom.json")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("Resolve = %q, want an absolute path", got)
	}
	if suffix := filepath.Join("target", "bom.json"); !strings.HasSuffix(got, suffix) {
		t.Errorf("Resolve = %q, want a path ending in %q", got, suffix)
	}
}

func TestResolveAbsolutePattern(t *testing.T) {
	base := t.TempDir()
	other := t.TempDir()
	want := writeFile(t, other, "target/products/bom.json")

	// baseDir is deliberately unrelated: an absolute pattern must not be
	// joined onto it.
	got, err := discover.Resolve(base, "rcp-client", filepath.Join(other, "target", "**", "bom.json"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != want {
		t.Errorf("Resolve = %q, want %q", got, want)
	}
}

func TestResolveNoMatch(t *testing.T) {
	base := t.TempDir()
	writeFile(t, base, "com.example.server/target/bom.json")

	const pattern = "com.example.client/target/**/bom.json"
	_, err := discover.Resolve(base, "rcp-client", pattern)
	if err == nil {
		t.Fatal("Resolve succeeded, want a no-match error")
	}

	var nm *discover.NoMatchError
	if !errors.As(err, &nm) {
		t.Fatalf("Resolve error is %T, want *discover.NoMatchError", err)
	}

	msg := err.Error()
	// §10: the message must name the artifact, the pattern as resolved, and
	// the absolute directory searched.
	for _, want := range []string{
		`"rcp-client"`,
		pattern,
		filepath.Join(base, "com.example.client", "target"),
		base,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("no-match message does not contain %q:\n%s", want, msg)
		}
	}
	if !filepath.IsAbs(nm.Dir) {
		t.Errorf("NoMatchError.Dir = %q, want an absolute path", nm.Dir)
	}
	if !filepath.IsAbs(nm.Resolved) {
		t.Errorf("NoMatchError.Resolved = %q, want an absolute path", nm.Resolved)
	}
}

func TestResolveNoMatchNamesTheMissingDirectory(t *testing.T) {
	base := t.TempDir()
	makeDir(t, base, "com.example.client")

	_, err := discover.Resolve(base, "rcp-client", "com.example.client/target/**/bom.json")
	if err == nil {
		t.Fatal("Resolve succeeded, want a no-match error")
	}

	// The build never ran, so the message should point at the exact component
	// where the path stops existing rather than at the whole pattern.
	missing := filepath.Join(base, "com.example.client", "target")
	if msg := err.Error(); !strings.Contains(msg, missing+" does not exist") {
		t.Errorf("no-match message does not report %q as missing:\n%s", missing, msg)
	}
}

func TestResolveSeveralMatches(t *testing.T) {
	base := t.TempDir()
	want := []string{
		writeFile(t, base, "target/products/a/bom.json"),
		writeFile(t, base, "target/products/b/bom.json"),
		writeFile(t, base, "target/products/c/bom.json"),
	}

	_, err := discover.Resolve(base, "rcp-client", "target/**/bom.json")
	if err == nil {
		t.Fatal("Resolve succeeded, want a several-matches error")
	}

	var mm *discover.MultipleMatchesError
	if !errors.As(err, &mm) {
		t.Fatalf("Resolve error is %T, want *discover.MultipleMatchesError", err)
	}
	if len(mm.Matches) != len(want) {
		t.Fatalf("MultipleMatchesError.Matches = %v, want %d entries", mm.Matches, len(want))
	}

	msg := err.Error()
	for _, path := range want {
		if !strings.Contains(msg, path) {
			t.Errorf("several-matches message does not list %q:\n%s", path, msg)
		}
	}
	if !strings.Contains(msg, `"rcp-client"`) {
		t.Errorf("several-matches message does not name the artifact:\n%s", msg)
	}
	if !strings.Contains(strings.ToLower(msg), "out of scope") {
		t.Errorf("several-matches message does not say merging is out of scope:\n%s", msg)
	}
}

func TestResolveSeveralMatchesAreSorted(t *testing.T) {
	base := t.TempDir()
	// Created out of order on purpose: readdir order is not lexical on every
	// filesystem and the message has to be byte identical across runs (§7).
	for _, rel := range []string{"target/z/bom.json", "target/a/bom.json", "target/m/bom.json"} {
		writeFile(t, base, rel)
	}

	var mm *discover.MultipleMatchesError
	_, err := discover.Resolve(base, "rcp-client", "target/**/bom.json")
	if !errors.As(err, &mm) {
		t.Fatalf("Resolve error is %T, want *discover.MultipleMatchesError", err)
	}

	want := []string{
		filepath.Join(base, "target", "a", "bom.json"),
		filepath.Join(base, "target", "m", "bom.json"),
		filepath.Join(base, "target", "z", "bom.json"),
	}
	for i := range want {
		if mm.Matches[i] != want[i] {
			t.Fatalf("Matches = %v, want %v", mm.Matches, want)
		}
	}

	_, second := discover.Resolve(base, "rcp-client", "target/**/bom.json")
	if err.Error() != second.Error() {
		t.Errorf("two runs produced different messages:\n%s\n---\n%s", err, second)
	}
}

func TestResolveDirectoryMatchingTheGlobIsNotAMatch(t *testing.T) {
	base := t.TempDir()
	// A directory literally named bom.json. cyclonedx-maven-plugin will never
	// produce one, but an unpacked product directory can.
	makeDir(t, base, "target/products/bom.json")

	_, err := discover.Resolve(base, "rcp-client", "target/**/bom.json")
	if err == nil {
		t.Fatal("Resolve succeeded, want a no-match error")
	}

	var nm *discover.NoMatchError
	if !errors.As(err, &nm) {
		t.Fatalf("Resolve error is %T, want *discover.NoMatchError", err)
	}

	dir := filepath.Join(base, "target", "products", "bom.json")
	msg := err.Error()
	if !strings.Contains(msg, dir) {
		t.Errorf("no-match message does not mention the matching directory %q:\n%s", dir, msg)
	}
	if !strings.Contains(strings.ToLower(msg), "directory") {
		t.Errorf("no-match message does not explain the directory was skipped:\n%s", msg)
	}
}

func TestResolveDirectoryDoesNotShadowTheFile(t *testing.T) {
	base := t.TempDir()
	makeDir(t, base, "target/products/bom.json")
	want := writeFile(t, base, "target/classes/bom.json")

	got, err := discover.Resolve(base, "rcp-client", "target/**/bom.json")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != want {
		t.Errorf("Resolve = %q, want %q", got, want)
	}
}

func TestResolveRejectsEmptyPattern(t *testing.T) {
	base := t.TempDir()

	var pe *discover.PatternError
	if _, err := discover.Resolve(base, "rcp-client", "   "); !errors.As(err, &pe) {
		t.Fatalf("Resolve error is %T, want *discover.PatternError", err)
	}
	if !strings.Contains(pe.Error(), `"rcp-client"`) {
		t.Errorf("pattern error does not name the artifact: %s", pe)
	}
}

func TestResolveRejectsMalformedPattern(t *testing.T) {
	base := t.TempDir()
	writeFile(t, base, "target/bom.json")

	var pe *discover.PatternError
	if _, err := discover.Resolve(base, "rcp-client", "target/[a-.json"); !errors.As(err, &pe) {
		t.Fatalf("Resolve error is %T, want *discover.PatternError", err)
	}
}

func TestResolveRejectsPatternNamingADirectory(t *testing.T) {
	base := t.TempDir()
	makeDir(t, base, "target")

	// "." collapses to the manifest directory itself, which can never be an
	// SBOM file.
	var pe *discover.PatternError
	if _, err := discover.Resolve(base, "rcp-client", "."); !errors.As(err, &pe) {
		t.Fatalf("Resolve error is %T, want *discover.PatternError", err)
	}
}
