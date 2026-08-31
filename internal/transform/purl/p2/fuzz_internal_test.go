package p2

import (
	"os"
	"strings"
	"testing"

	"github.com/package-url/packageurl-go"
)

// FuzzLoadTable drives the mapping table parser with arbitrary JSON. An
// operator supplies this file, so a broken one has to be rejected rather than
// half-loaded: the parser's own rule is that half an entry is worse than no
// entry, because it produces a purl with an empty segment that looks
// resolvable and is not.
func FuzzLoadTable(f *testing.F) {
	if data, err := os.ReadFile("p2-maven.json"); err == nil {
		f.Add(data)
	}
	f.Add([]byte(`{"schemaVersion":1,"entries":{}}`))
	f.Add([]byte(`{"schemaVersion":1,"entries":{"org.example":{"groupId":"g","artifactId":"a"}}}`))
	f.Add([]byte(`{"schemaVersion":1,"entries":{"org.example":{"groupId":"","artifactId":"a"}}}`))
	f.Add([]byte(`{"schemaVersion":2,"entries":{}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		tbl, err := loadTable(data, "fuzz")
		if err != nil {
			if tbl != nil {
				t.Fatalf("loadTable returned both a table and an error %v", err)
			}
			if !strings.Contains(err.Error(), "fuzz") {
				t.Fatalf("error does not name the source file: %v", err)
			}
			return
		}
		for bsn, c := range tbl {
			if c.GroupID == "" || c.ArtifactID == "" {
				t.Fatalf("entry %q loaded with a half-empty coordinate %+v", bsn, c)
			}
		}
	})
}

// FuzzSplitPURL checks the hand-rolled purl splitter. rio splits rather than
// re-encodes so a component's string survives untouched, which only holds if
// the three pieces still reassemble into exactly the input.
func FuzzSplitPURL(f *testing.F) {
	f.Add("pkg:maven/org.example/artifact@1.2.3")
	f.Add("pkg:p2/org.example.bundle@1.2.3.v20240101")
	f.Add("pkg:maven/g/a@1.0?type=jar")
	f.Add("pkg:maven/g/a@1.0#subpath")
	f.Add("pkg:maven/g/a")
	f.Add("@")
	f.Add("")

	f.Fuzz(func(t *testing.T, purl string) {
		head, version, tail, ok := splitPURL(purl)
		if !ok {
			if head != "" || version != "" || tail != "" {
				t.Fatalf("splitPURL failed but returned %q/%q/%q", head, version, tail)
			}
			return
		}
		if got := head + version + tail; got != purl {
			t.Fatalf("pieces do not reassemble: %q + %q + %q = %q, want %q",
				head, version, tail, got, purl)
		}
		if !strings.HasSuffix(head, "@") {
			t.Fatalf("head %q does not end at the version separator", head)
		}
	})
}

// FuzzSplitVersionQualifier checks §6.1. Whatever is dropped from an Eclipse
// version has to be recoverable, or rio has silently discarded build
// information it claimed only to move.
func FuzzSplitVersionQualifier(f *testing.F) {
	f.Add("1.2.3.v20240101")
	f.Add("1.2.3.4")
	f.Add("1.2.3")
	f.Add("1.2.3.")
	f.Add("")

	f.Fuzz(func(t *testing.T, version string) {
		base, dropped := splitVersionQualifier(version)
		if dropped == "" {
			if base != version {
				t.Fatalf("nothing was dropped but the version changed: %q became %q", version, base)
			}
			return
		}
		if got := base + "." + dropped; got != version {
			t.Fatalf("dropped segment is not recoverable: %q + %q = %q, want %q",
				base, dropped, got, version)
		}
	})
}

// FuzzCoordinatesValid is the guard that matters most here. packageurl-go only
// refuses an empty name, so a groupId of "com/example" would silently become
// the nested namespace pkg:maven/com/example/artifact — plausible, and
// resolving to nothing. These values are read out of the SBOM, so they are as
// untrusted as the document. Whatever valid() accepts must therefore survive
// the round trip through a purl unchanged.
func FuzzCoordinatesValid(f *testing.F) {
	f.Add("org.example", "artifact", "1.2.3")
	f.Add("com/example", "artifact", "1.0")
	f.Add("org.example", "art@ifact", "1.0")
	f.Add(" org.example ", "artifact", "1.0")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, group, artifact, version string) {
		c := Coordinates{GroupID: group, ArtifactID: artifact}
		reason, ok := c.valid()
		if !ok {
			if reason == "" {
				t.Fatal("coordinates were rejected without a reason")
			}
			return
		}
		if reason != "" {
			t.Fatalf("coordinates were accepted but carried the reason %q", reason)
		}
		parsed, err := packageurl.FromString(mavenPURL(c, version))
		if err != nil {
			t.Fatalf("valid coordinates %+v produced an unparseable purl: %v", c, err)
		}
		if parsed.Namespace != group {
			t.Fatalf("groupId did not survive: %q became namespace %q", group, parsed.Namespace)
		}
		if parsed.Name != artifact {
			t.Fatalf("artifactId did not survive: %q became name %q", artifact, parsed.Name)
		}
	})
}
