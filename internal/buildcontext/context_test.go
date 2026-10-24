package buildcontext_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/buildcontext"
)

func TestReadResolveSelectsExactArtifactAndBuildsDeterministicFields(t *testing.T) {
	dir := t.TempDir()
	first := []byte("first original SBOM")
	second := []byte("second original SBOM")
	writeContext(t, dir, `{
  "contextVersion": 1,
  "artifacts": [
    {"id":"one","sbom":{"sha256":"`+digest(first)+`"},"source":{"repository":"https://example.org/one","workspace":"clean"},"build":{"url":"https://ci.example.org/one"}},
    {"id":"two","sbom":{"sha256":"`+digest(second)+`"},"source":{"repository":"https://example.org/two","revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"lifecycle":"build"}
  ]
}`)

	f, err := buildcontext.Read(dir, "build-context.json")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := f.Resolve("two", digest(second), buildcontext.Binding{File: "build-context.json", Require: []string{"source.revision"}})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.File.Path != "build-context.json" || resolved.File.SHA256 != digest(mustRead(t, filepath.Join(dir, "build-context.json"))) {
		t.Fatalf("file = %+v", resolved.File)
	}
	if resolved.Selector != "/artifacts/1" || resolved.Artifact.ID != "two" {
		t.Fatalf("resolved = %+v", resolved)
	}
	if resolved.Artifact.Source == nil || resolved.Artifact.Source.Workspace == nil || *resolved.Artifact.Source.Workspace != "unknown" {
		t.Fatalf("effective workspace = %+v, want defaulted unknown", resolved.Artifact.Source)
	}
	if got, want := resolved.Defaulted, []string{"source.workspace"}; !sameStrings(got, want) {
		t.Fatalf("defaulted = %q, want %q", got, want)
	}
	if len(resolved.Fields) != 4 {
		t.Fatalf("fields = %+v", resolved.Fields)
	}
	for i, field := range resolved.Fields {
		if i > 0 && resolved.Fields[i-1].Name >= field.Name {
			t.Fatalf("fields not sorted: %+v", resolved.Fields)
		}
	}
	for _, want := range []struct {
		name, value, selector string
		defaulted             bool
	}{
		{"lifecycle", "build", "/artifacts/1/lifecycle", false},
		{"source.repository", "https://example.org/two", "/artifacts/1/source/repository", false},
		{"source.revision", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "/artifacts/1/source/revision", false},
		{"source.workspace", "unknown", "/artifacts/1/source", true},
	} {
		got := findField(t, resolved.Fields, want.name)
		if got.Value != want.value || got.Selector != want.selector || got.Defaulted != want.defaulted {
			t.Fatalf("field %s = %+v, want %+v", want.name, got, want)
		}
	}
	// Resolve returns a safe copy: making a caller-side change cannot leak to a
	// subsequent artifact resolution from the same shared file.
	*resolved.Artifact.Source.Repository = "changed"
	again, err := f.Resolve("one", digest(first), buildcontext.Binding{File: "build-context.json"})
	if err != nil {
		t.Fatal(err)
	}
	if again.Artifact.Source == nil || again.Artifact.Source.Repository == nil || *again.Artifact.Source.Repository != "https://example.org/one" {
		t.Fatalf("resolution mutated shared context: %+v", again.Artifact)
	}
}

func TestReadRecordsContextPathRelativeToManifest(t *testing.T) {
	dir := t.TempDir()
	writeContext(t, dir, `{"contextVersion":1,"artifacts":[{"id":"app","sbom":{"sha256":"`+strings.Repeat("a", 64)+`"}}]}`)
	contextFile := filepath.Join(dir, "build-context.json")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relBase, relErr := filepath.Rel(wd, dir)

	for _, tc := range []struct {
		name, base, file, want string
	}{
		{"relative base and absolute file", relBase, contextFile, "build-context.json"},
		{"absolute base and absolute file", dir, contextFile, "build-context.json"},
		{"upward file", filepath.Join(dir, "nested"), contextFile, "../build-context.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "relative base and absolute file" && relErr != nil {
				t.Skipf("working directory and temporary file are on different volumes: %v", relErr)
			}
			f, err := buildcontext.Read(tc.base, tc.file)
			if err != nil {
				t.Fatal(err)
			}
			resolved, err := f.Resolve("app", strings.Repeat("a", 64), buildcontext.Binding{File: tc.file})
			if err != nil {
				t.Fatal(err)
			}
			if resolved.File.Path != tc.want {
				t.Fatalf("recorded file path = %q, want %q", resolved.File.Path, tc.want)
			}
		})
	}
}

func TestReadRejectsContextOnDifferentWindowsVolume(t *testing.T) {
	if os.PathSeparator != '\\' {
		t.Skip("Windows volume boundary")
	}
	dir := t.TempDir()
	writeContext(t, dir, `{"contextVersion":1,"artifacts":[{"id":"app","sbom":{"sha256":"`+strings.Repeat("a", 64)+`"}}]}`)
	volume := strings.ToUpper(filepath.VolumeName(dir))
	other := `C:\manifest`
	if volume == "C:" {
		other = `D:\manifest`
	}
	_, err := buildcontext.Read(other, filepath.Join(dir, "build-context.json"))
	if err == nil || !strings.Contains(err.Error(), "relative") || !strings.Contains(err.Error(), "context") {
		t.Fatalf("error = %v, want context relative-path refusal", err)
	}
}

func TestReadRejectsStrictInvalidDocuments(t *testing.T) {
	validDigest := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, body, want string
	}{
		{"unknown key", `{"contextVersion":1,"artifacts":[],"extra":1}`, "unknown key"},
		{"unknown nested key", `{"contextVersion":1,"artifacts":[{"id":"a","sbom":{"sha256":"` + validDigest + `"},"source":{"unknown":"x"}}]}`, "unknown key"},
		{"duplicate nested", `{"contextVersion":1,"artifacts":[{"id":"a","id":"b","sbom":{"sha256":"` + validDigest + `"}}]}`, "duplicate key"},
		{"null", `{"contextVersion":1,"artifacts":[{"id":null,"sbom":{"sha256":"` + validDigest + `"}}]}`, "id"},
		{"version", `{"contextVersion":2,"artifacts":[]}`, "contextVersion"},
		{"empty artifacts", `{"contextVersion":1,"artifacts":[]}`, "artifacts"},
		{"bad digest", `{"contextVersion":1,"artifacts":[{"id":"a","sbom":{"sha256":"ABC"}}]}`, "sha256"},
		{"blank", `{"contextVersion":1,"artifacts":[{"id":" ","sbom":{"sha256":"` + validDigest + `"}}]}`, "id"},
		{"control character", `{"contextVersion":1,"artifacts":[{"id":"a\u001f","sbom":{"sha256":"` + validDigest + `"}}]}`, "id"},
		{"credentials hidden", `{"contextVersion":1,"artifacts":[{"id":"a","sbom":{"sha256":"` + validDigest + `"},"source":{"repository":"https://user:secret@example.org/x"}}]}`, "repository"},
		{"raw repository query", `{"contextVersion":1,"artifacts":[{"id":"a","sbom":{"sha256":"` + validDigest + `"},"source":{"repository":"https://example.org/x?"}}]}`, "repository"},
		{"raw build fragment", `{"contextVersion":1,"artifacts":[{"id":"a","sbom":{"sha256":"` + validDigest + `"},"build":{"url":"https://example.org/x#"}}]}`, "build.url"},
		{"bad path", `{"contextVersion":1,"artifacts":[{"id":"a","sbom":{"sha256":"` + validDigest + `"},"source":{"subdirectory":"../x"}}]}`, "subdirectory"},
		{"bad lifecycle", `{"contextVersion":1,"artifacts":[{"id":"a","sbom":{"sha256":"` + validDigest + `"},"lifecycle":"ship"}]}`, "lifecycle"},
		{"empty source", `{"contextVersion":1,"artifacts":[{"id":"a","sbom":{"sha256":"` + validDigest + `"},"source":{}}]}`, "source"},
		{"bad timestamp", `{"contextVersion":1,"artifacts":[{"id":"a","sbom":{"sha256":"` + validDigest + `"},"build":{"timestamp":"tomorrow"}}]}`, "timestamp"},
		{"tool without name", `{"contextVersion":1,"artifacts":[{"id":"a","sbom":{"sha256":"` + validDigest + `"},"generator":{"version":"1"}}]}`, "generator.name"},
		{"duplicate artifact", `{"contextVersion":1,"artifacts":[{"id":"a","sbom":{"sha256":"` + validDigest + `"}},{"id":"a","sbom":{"sha256":"` + validDigest + `"}}]}`, "duplicate"},
		{"trailing document", `{"contextVersion":1,"artifacts":[{"id":"a","sbom":{"sha256":"` + validDigest + `"}}]} {}`, "trailing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeContext(t, dir, tc.body)
			_, err := buildcontext.Read(dir, "build-context.json")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("error leaked URL credentials: %v", err)
			}
		})
	}
}

func TestResolveRequiresExplicitValuesAndChecksIdentity(t *testing.T) {
	dir := t.TempDir()
	input := []byte("original SBOM")
	writeContext(t, dir, `{"contextVersion":1,"artifacts":[{"id":"app","sbom":{"sha256":"`+digest(input)+`"},"source":{"repository":"https://example.org/app"}}]}`)
	f, err := buildcontext.Read(dir, "build-context.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, id, sum, want string
		binding             buildcontext.Binding
	}{
		{"missing id", "other", digest(input), "other", buildcontext.Binding{File: "build-context.json"}},
		{"wrong digest", "app", strings.Repeat("b", 64), "sha256", buildcontext.Binding{File: "build-context.json"}},
		{"required default", "app", digest(input), "source.workspace", buildcontext.Binding{File: "build-context.json", Require: []string{"source.workspace"}}},
		{"unknown require", "app", digest(input), "require", buildcontext.Binding{File: "build-context.json", Require: []string{"source.nope"}}},
		{"lifecycle replace", "app", digest(input), "replace", buildcontext.Binding{File: "build-context.json", Replace: []string{"lifecycle"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.Resolve(tc.id, tc.sum, tc.binding)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidateBindingAcceptsNoopReplacementAndRejectsBadSelectors(t *testing.T) {
	if err := buildcontext.ValidateBinding(nil); err != nil {
		t.Fatal(err)
	}
	if err := buildcontext.ValidateBinding(&buildcontext.Binding{File: "ctx.json", Replace: []string{"build.id"}}); err != nil {
		t.Fatal(err)
	}
	for _, binding := range []*buildcontext.Binding{
		{File: ""},
		{File: "ctx.json", Require: []string{"source.repository", "source.repository"}},
		{File: "ctx.json", Replace: []string{"source.nope"}},
		{File: "ctx.json", Replace: []string{"lifecycle"}},
	} {
		if err := buildcontext.ValidateBinding(binding); err == nil {
			t.Fatalf("binding %+v was accepted", binding)
		}
	}
}

func writeContext(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "build-context.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func findField(t *testing.T, fields []buildcontext.Field, name string) buildcontext.Field {
	t.Helper()
	for _, field := range fields {
		if field.Name == name {
			return field
		}
	}
	t.Fatalf("missing field %q in %+v", name, fields)
	return buildcontext.Field{}
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestDistributionsParseResolveAndClone(t *testing.T) {
	dir := t.TempDir()
	input := []byte("original SBOM")
	sumA, sumB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	writeContext(t, dir, `{"contextVersion":1,"artifacts":[{"id":"app","sbom":{"sha256":"`+digest(input)+`"},"distributions":[{"name":"app.tar.gz","sha256":"`+sumA+`","url":"https://example.org/dl/app.tar.gz"},{"name":"app.zip","sha256":"`+sumB+`"}]}]}`)
	f, err := buildcontext.Read(dir, "build-context.json")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := f.Resolve("app", digest(input), buildcontext.Binding{File: "build-context.json"})
	if err != nil {
		t.Fatal(err)
	}
	want := []buildcontext.Distribution{
		{Name: "app.tar.gz", SHA256: sumA, URL: "https://example.org/dl/app.tar.gz"},
		{Name: "app.zip", SHA256: sumB},
	}
	if len(resolved.Artifact.Distributions) != 2 || resolved.Artifact.Distributions[0] != want[0] || resolved.Artifact.Distributions[1] != want[1] {
		t.Fatalf("distributions = %+v, want %+v", resolved.Artifact.Distributions, want)
	}
	for _, field := range resolved.Fields {
		if strings.Contains(field.Name, "distribution") {
			t.Fatalf("distributions leaked into selectors: %+v", field)
		}
	}
	resolved.Artifact.Distributions[0].Name = "changed"
	again, err := f.Resolve("app", digest(input), buildcontext.Binding{File: "build-context.json"})
	if err != nil {
		t.Fatal(err)
	}
	if again.Artifact.Distributions[0] != want[0] {
		t.Fatalf("resolve shares distribution storage: %+v", again.Artifact.Distributions[0])
	}
	if err := buildcontext.ValidateBinding(&buildcontext.Binding{File: "build-context.json", Replace: []string{"distributions"}}); err == nil {
		t.Fatal("distributions accepted as a replace selector")
	}
}

func TestDistributionsRejectInvalid(t *testing.T) {
	sum := strings.Repeat("a", 64)
	entry := func(dists string) string {
		return `{"contextVersion":1,"artifacts":[{"id":"a","sbom":{"sha256":"` + sum + `"},"distributions":` + dists + `}]}`
	}
	var many []string
	for i := 0; i < 1001; i++ {
		many = append(many, `{"name":"f`+strings.Repeat("x", i%7)+string(rune('a'+i%26))+strings.Repeat("y", i/26)+`","sha256":"`+sum+`"}`)
	}
	for _, tc := range []struct{ name, body, want string }{
		{"empty array", entry(`[]`), "artifacts[0].distributions"},
		{"missing name", entry(`[{"sha256":"` + sum + `"}]`), "artifacts[0].distributions[0].name"},
		{"missing sha256", entry(`[{"name":"a"}]`), "artifacts[0].distributions[0].sha256"},
		{"uppercase sha256", entry(`[{"name":"a","sha256":"` + strings.Repeat("A", 64) + `"}]`), "artifacts[0].distributions[0].sha256"},
		{"short sha256", entry(`[{"name":"a","sha256":"abc"}]`), "artifacts[0].distributions[0].sha256"},
		{"slash name", entry(`[{"name":"dir/a","sha256":"` + sum + `"}]`), "artifacts[0].distributions[0].name"},
		{"backslash name", entry(`[{"name":"dir\\a","sha256":"` + sum + `"}]`), "artifacts[0].distributions[0].name"},
		{"padded name", entry(`[{"name":" a","sha256":"` + sum + `"}]`), "artifacts[0].distributions[0].name"},
		{"duplicate name", entry(`[{"name":"a","sha256":"` + sum + `"},{"name":"a","sha256":"` + sum + `"}]`), "artifacts[0].distributions[1].name"},
		{"bad url", entry(`[{"name":"a","sha256":"` + sum + `","url":"https://u:p@example.org/a"}]`), "artifacts[0].distributions[0].url"},
		{"unknown key", entry(`[{"name":"a","sha256":"` + sum + `","size":1}]`), "unknown key"},
		{"null", entry(`null`), "artifacts[0].distributions"},
		{"wrong type", entry(`{"name":"a"}`), "artifacts[0].distributions"},
		{"entry wrong type", entry(`["a"]`), "artifacts[0].distributions[0]"},
		{"too many", entry(`[` + strings.Join(many, ",") + `]`), "at most 1000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeContext(t, dir, tc.body)
			_, err := buildcontext.Read(dir, "build-context.json")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseEffectiveAcceptsDistributions(t *testing.T) {
	sum := strings.Repeat("a", 64)
	a, err := buildcontext.ParseEffective([]byte(`{"id":"a","sbom":{"sha256":"` + sum + `"},"distributions":[{"name":"x","sha256":"` + sum + `"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Distributions) != 1 || a.Distributions[0].Name != "x" {
		t.Fatalf("distributions = %+v", a.Distributions)
	}
	if _, err := buildcontext.ParseEffective([]byte(`{"id":"a","sbom":{"sha256":"` + sum + `"},"distributions":[]}`)); err == nil {
		t.Fatal("empty distributions accepted")
	}
}
