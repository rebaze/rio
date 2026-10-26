package sbom_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/rebaze/rio/internal/sbom"
)

func TestProfileViews(t *testing.T) {
	doc := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6",
"metadata":{"component":{"name":"app","components":[{"name":"f","components":[{"name":"g"}]}]}},
"components":[{"name":"x","components":[{"name":"y"}]},"junk"],
"dependencies":[{"ref":"a"},{"ref":"b"},{"ref":7}],
"compositions":[{"aggregate":"complete","dependencies":["a"]},{"aggregate":"not_specified","assemblies":["b"]},{"aggregate":"unknown","assemblies":["c"]}],
"vulnerabilities":[]}`))

	type pc struct {
		Path    string
		Subject bool
		Nil     bool
	}
	var got []pc
	for _, c := range doc.ProfileComponents() {
		got = append(got, pc{c.Path, c.Subject, c.Object == nil})
	}
	want := []pc{
		{"metadata.component", true, false},
		{"metadata.component.components[0]", false, false},
		{"metadata.component.components[0].components[0]", false, false},
		{"components[0]", false, false},
		{"components[0].components[0]", false, false},
		{"components[1]", false, true},
	}
	if d := cmp.Diff(want, got); d != "" {
		t.Errorf("ProfileComponents() mismatch (-want +got):\n%s", d)
	}
	if doc.MetadataObject() == nil {
		t.Error("MetadataObject() = nil, want object")
	}
	if d := cmp.Diff(map[string]bool{"a": true, "b": true}, doc.DependencyEntries()); d != "" {
		t.Errorf("DependencyEntries() mismatch:\n%s", d)
	}
	if d := cmp.Diff(map[string]bool{"a": true, "c": true}, doc.CompositionCoverage()); d != "" {
		t.Errorf("CompositionCoverage() mismatch:\n%s", d)
	}
	if doc.HasVulnerabilities() {
		t.Error("HasVulnerabilities() = true for [], want false")
	}
	if !load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{}]}`)).HasVulnerabilities() {
		t.Error("HasVulnerabilities() = false for one entry, want true")
	}
	if load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)).MetadataObject() != nil {
		t.Error("MetadataObject() non-nil for absent metadata")
	}

}

func TestAtLeast(t *testing.T) {
	for _, c := range []struct {
		spec, floor string
		want        bool
	}{{"1.6", "1.6", true}, {"1.7", "1.6", true}, {"1.5", "1.6", false}, {"1.10", "1.6", true}} {
		if got := sbom.AtLeast(c.spec, c.floor); got != c.want {
			t.Errorf("AtLeast(%q,%q) = %v, want %v", c.spec, c.floor, got, c.want)
		}
	}
}
