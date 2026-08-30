package gate_test

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/rebaze/rio/internal/gate"
	"github.com/rebaze/rio/internal/sbom"
)

// load builds a Document from an inline literal. Every fixture in this file is
// small and self describing; the shared testdata trees are for the pipeline.
func load(t *testing.T, doc string) *sbom.Document {
	t.Helper()
	d, err := sbom.Load([]byte(doc))
	if err != nil {
		t.Fatalf("loading fixture: %v", err)
	}
	return d
}

const goodSubject = `"metadata": {"component": {"type": "application", "name": "rcp-client", "version": "4.2.0"}}`

func docWith(subject string, components ...string) string {
	body := `{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1`
	if subject != "" {
		body += ", " + subject
	}
	body += `, "components": [`
	for i, c := range components {
		if i > 0 {
			body += ", "
		}
		body += c
	}
	return body + "]}"
}

const (
	compGson    = `{"type": "library", "name": "gson", "group": "com.google.code.gson", "version": "2.8.9", "purl": "pkg:maven/com.google.code.gson/gson@2.8.9"}`
	compNoVer   = `{"type": "library", "name": "legacy-adapter", "group": "com.tkse", "purl": "pkg:maven/com.tkse/legacy-adapter"}`
	compNoName  = `{"type": "library", "version": "1.0.0", "purl": "pkg:maven/com.tkse/nameless@1.0.0"}`
	compNoPURL  = `{"type": "library", "name": "internal-tool", "group": "com.tkse", "version": "3.1.0"}`
	compBadPURL = `{"type": "library", "name": "broken", "version": "1.0.0", "purl": "definitely not a purl"}`
	compP2      = `{"type": "library", "name": "com.example.internal", "version": "1.0.0", "purl": "pkg:p2/com.example.internal@1.0.0.v20240101?classifier=osgi.bundle"}`
	compBare    = `{"type": "library"}`
)

func all() []gate.Requirement {
	return []gate.Requirement{gate.RequireName, gate.RequireVersion, gate.RequirePURL}
}

func TestCheckAllPass(t *testing.T) {
	got := gate.Check(load(t, docWith(goodSubject, compGson, compP2)), all())

	if !got.OK() {
		t.Fatalf("OK() = false, want true; findings: %+v", got.Findings)
	}
	if got.Findings == nil {
		t.Error("Findings is nil; want a non-nil empty slice so index.json carries [] not null (§4.2)")
	}
	if len(got.Findings) != 0 {
		t.Errorf("Findings = %+v, want empty", got.Findings)
	}
}

func TestAllRequirements(t *testing.T) {
	if diff := cmp.Diff(all(), gate.All()); diff != "" {
		t.Errorf("All() mismatch (-want +got):\n%s", diff)
	}
}

func TestSubjectMissingName(t *testing.T) {
	doc := load(t, docWith(`"metadata": {"component": {"type": "application", "version": "4.2.0"}}`, compGson))

	got := gate.Check(doc, all())

	want := []gate.Finding{{Subject: true, Missing: []string{"name"}}}
	if diff := cmp.Diff(want, got.Findings); diff != "" {
		t.Errorf("Findings mismatch (-want +got):\n%s", diff)
	}
	if got.OK() {
		t.Error("OK() = true, want false")
	}
}

func TestSubjectMissingVersion(t *testing.T) {
	doc := load(t, docWith(`"metadata": {"component": {"type": "application", "name": "rcp-client", "version": ""}}`, compGson))

	got := gate.Check(doc, all())

	want := []gate.Finding{{Subject: true, Missing: []string{"version"}}}
	if diff := cmp.Diff(want, got.Findings); diff != "" {
		t.Errorf("Findings mismatch (-want +got):\n%s", diff)
	}
}

func TestSubjectAbsentEntirely(t *testing.T) {
	// No metadata at all: both halves of the subject are missing, in the fixed
	// name-then-version order.
	got := gate.Check(load(t, docWith("", compGson)), all())

	want := []gate.Finding{{Subject: true, Missing: []string{"name", "version"}}}
	if diff := cmp.Diff(want, got.Findings); diff != "" {
		t.Errorf("Findings mismatch (-want +got):\n%s", diff)
	}
}

// The subject fails the artifact regardless of what gate.require asks for, so
// an empty require still catches it (§5 step 4).
func TestSubjectFailsWithEmptyRequire(t *testing.T) {
	doc := load(t, docWith(`"metadata": {"component": {"type": "application", "name": "rcp-client"}}`, compNoVer, compNoPURL))

	got := gate.Check(doc, nil)

	want := []gate.Finding{{Subject: true, Missing: []string{"version"}}}
	if diff := cmp.Diff(want, got.Findings); diff != "" {
		t.Errorf("Findings mismatch (-want +got):\n%s", diff)
	}
}

func TestEmptyRequireChecksOnlySubject(t *testing.T) {
	// A good subject plus components that would fail every requirement.
	got := gate.Check(load(t, docWith(goodSubject, compNoVer, compNoPURL, compBadPURL)), nil)

	if !got.OK() {
		t.Errorf("OK() = false, want true; findings: %+v", got.Findings)
	}
}

func TestComponentMissingVersion(t *testing.T) {
	got := gate.Check(load(t, docWith(goodSubject, compGson, compNoVer)), all())

	want := []gate.Finding{{
		Component: "pkg:maven/com.tkse/legacy-adapter",
		Missing:   []string{"version"},
	}}
	if diff := cmp.Diff(want, got.Findings); diff != "" {
		t.Errorf("Findings mismatch (-want +got):\n%s", diff)
	}
}

func TestComponentMissingName(t *testing.T) {
	got := gate.Check(load(t, docWith(goodSubject, compNoName)), all())

	want := []gate.Finding{{
		Component: "pkg:maven/com.tkse/nameless@1.0.0",
		Missing:   []string{"name"},
	}}
	if diff := cmp.Diff(want, got.Findings); diff != "" {
		t.Errorf("Findings mismatch (-want +got):\n%s", diff)
	}
}

func TestComponentMissingPURL(t *testing.T) {
	got := gate.Check(load(t, docWith(goodSubject, compNoPURL)), all())

	// No purl to name it by, so the human readable group:name@version form.
	want := []gate.Finding{{
		Component: "com.tkse:internal-tool@3.1.0",
		Missing:   []string{"purl"},
	}}
	if diff := cmp.Diff(want, got.Findings); diff != "" {
		t.Errorf("Findings mismatch (-want +got):\n%s", diff)
	}
}

func TestComponentUnparseablePURL(t *testing.T) {
	got := gate.Check(load(t, docWith(goodSubject, compBadPURL)), all())

	want := []gate.Finding{{
		Component: "definitely not a purl",
		Missing:   []string{"purl"},
	}}
	if diff := cmp.Diff(want, got.Findings); diff != "" {
		t.Errorf("Findings mismatch (-want +got):\n%s", diff)
	}
}

func TestUnparseablePURLVariants(t *testing.T) {
	for _, purl := range []string{
		"not-a-purl",
		"pkg:",
		"pkg:maven",
		"maven/com.tkse/thing@1.0.0",
		"pkg:2bad/com.tkse/thing@1.0.0",
	} {
		comp := `{"type": "library", "name": "n", "version": "1.0.0", "purl": ` + mustJSON(t, purl) + `}`
		got := gate.Check(load(t, docWith(goodSubject, comp)), []gate.Requirement{gate.RequirePURL})
		if got.OK() {
			t.Errorf("purl %q passed the gate, want a finding", purl)
		}
	}
}

// A purl left at pkg:p2 by the transform is still a valid purl, so it passes.
// Unmapped is a count in index.json, not a gate failure (§5 step 4).
func TestP2PURLPasses(t *testing.T) {
	got := gate.Check(load(t, docWith(goodSubject, compP2)), all())

	if !got.OK() {
		t.Errorf("a pkg:p2 purl failed the gate: %+v", got.Findings)
	}
}

func TestRequireSubsetOnlyName(t *testing.T) {
	// compNoVer and compNoPURL each fail a requirement that was not asked for.
	got := gate.Check(load(t, docWith(goodSubject, compNoVer, compNoPURL, compNoName)), []gate.Requirement{gate.RequireName})

	want := []gate.Finding{{
		Component: "pkg:maven/com.tkse/nameless@1.0.0",
		Missing:   []string{"name"},
	}}
	if diff := cmp.Diff(want, got.Findings); diff != "" {
		t.Errorf("Findings mismatch (-want +got):\n%s", diff)
	}
}

func TestRequireSubsetVersionAndPURL(t *testing.T) {
	got := gate.Check(load(t, docWith(goodSubject, compNoName)), []gate.Requirement{gate.RequireVersion, gate.RequirePURL})

	if !got.OK() {
		t.Errorf("OK() = false, want true; findings: %+v", got.Findings)
	}
}

// Missing is ordered name, version, purl whatever order require arrived in, so
// index.json is byte identical across runs (§7).
func TestMissingOrderIsFixed(t *testing.T) {
	orders := [][]gate.Requirement{
		{gate.RequireName, gate.RequireVersion, gate.RequirePURL},
		{gate.RequirePURL, gate.RequireVersion, gate.RequireName},
		{gate.RequireVersion, gate.RequirePURL, gate.RequireName},
		// Duplicates must not duplicate the entries either.
		{gate.RequirePURL, gate.RequirePURL, gate.RequireName, gate.RequireVersion, gate.RequireName},
	}
	for _, require := range orders {
		got := gate.Check(load(t, docWith(goodSubject, compBare)), require)
		want := []gate.Finding{{Component: "components[0]", Missing: []string{"name", "version", "purl"}}}
		if diff := cmp.Diff(want, got.Findings); diff != "" {
			t.Errorf("require %v: Findings mismatch (-want +got):\n%s", require, diff)
		}
	}
}

func TestUnknownRequirementIgnored(t *testing.T) {
	// Manifest validation rejects these (§2); the gate simply checks nothing
	// it does not know how to check.
	got := gate.Check(load(t, docWith(goodSubject, compNoVer)), []gate.Requirement{"licence", "name"})

	if !got.OK() {
		t.Errorf("OK() = false, want true; findings: %+v", got.Findings)
	}
}

func TestFindingOrderSubjectFirstThenDocumentOrder(t *testing.T) {
	doc := load(t, docWith(`"metadata": {"component": {"type": "application", "name": "rcp-client"}}`,
		compGson, compNoVer, compP2, compNoPURL))

	got := gate.Check(doc, all())

	want := []gate.Finding{
		{Subject: true, Missing: []string{"version"}},
		{Component: "pkg:maven/com.tkse/legacy-adapter", Missing: []string{"version"}},
		{Component: "com.tkse:internal-tool@3.1.0", Missing: []string{"purl"}},
	}
	if diff := cmp.Diff(want, got.Findings); diff != "" {
		t.Errorf("Findings mismatch (-want +got):\n%s", diff)
	}
}

func TestComponentIdentityFallbacks(t *testing.T) {
	cases := []struct {
		name string
		comp string
		want string
	}{
		{"purl wins", `{"type": "library", "name": "n", "group": "g", "purl": "pkg:maven/g/n@1.0.0"}`, "pkg:maven/g/n@1.0.0"},
		{"group name version", `{"type": "library", "name": "n", "group": "g", "version": "1.0.0"}`, "g:n@1.0.0"},
		{"name and version", `{"type": "library", "name": "n", "version": "1.0.0"}`, "n@1.0.0"},
		{"name only", `{"type": "library", "name": "n"}`, "n"},
		{"group only", `{"type": "library", "group": "g"}`, "g"},
		{"nothing at all", `{"type": "library"}`, "components[0]"},
		// The version is the only value this component has; a bare
		// "components[0]" would throw it away (§10).
		{"version only", `{"type": "library", "version": "1.0.0"}`, "components[0]@1.0.0"},
		{"whitespace name is not identity", `{"type": "library", "name": "  ", "version": "1.0.0"}`, "components[0]@1.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := gate.Check(load(t, docWith(goodSubject, tc.comp)), all())
			if len(got.Findings) != 1 {
				t.Fatalf("Findings = %+v, want exactly one", got.Findings)
			}
			if got.Findings[0].Component != tc.want {
				t.Errorf("Component = %q, want %q", got.Findings[0].Component, tc.want)
			}
		})
	}
}

// The gate reads. It does not modify the document (§5 step 4).
func TestCheckDoesNotMutateDocument(t *testing.T) {
	doc := load(t, docWith(`"metadata": {"component": {"type": "application"}}`,
		compGson, compNoVer, compNoName, compNoPURL, compBadPURL, compP2, compBare))

	before, err := doc.Bytes()
	if err != nil {
		t.Fatalf("serializing before: %v", err)
	}

	got := gate.Check(doc, all())
	if got.OK() {
		t.Fatal("fixture was meant to fail the gate")
	}

	after, err := doc.Bytes()
	if err != nil {
		t.Fatalf("serializing after: %v", err)
	}
	if diff := cmp.Diff(string(before), string(after)); diff != "" {
		t.Errorf("Check mutated the document (-before +after):\n%s", diff)
	}
}

// The finding shape is the index.json contract (§4.2).
func TestFindingJSONShape(t *testing.T) {
	cases := []struct {
		finding gate.Finding
		want    string
	}{
		{gate.Finding{Component: "pkg:maven/com.tkse/legacy-adapter", Missing: []string{"version"}},
			`{"component":"pkg:maven/com.tkse/legacy-adapter","missing":["version"]}`},
		{gate.Finding{Subject: true, Missing: []string{"name", "version"}},
			`{"subject":true,"missing":["name","version"]}`},
	}
	for _, tc := range cases {
		b, err := json.Marshal(tc.finding)
		if err != nil {
			t.Fatalf("marshalling: %v", err)
		}
		if string(b) != tc.want {
			t.Errorf("Marshal() = %s, want %s", b, tc.want)
		}
	}
}

func TestCheckHandlesNoComponents(t *testing.T) {
	doc := load(t, `{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, `+goodSubject+`}`)

	if got := gate.Check(doc, all()); !got.OK() {
		t.Errorf("OK() = false, want true; findings: %+v", got.Findings)
	}
}

func mustJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshalling %q: %v", s, err)
	}
	return string(b)
}

// §5 step 4 evaluates every component, and a component nested under another is
// still shipped. The gate only reads, so unlike the transform layer it is not
// confined to the top-level array.
func TestNestedComponentsAreGated(t *testing.T) {
	doc := load(t, `{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
"metadata": {"component": {"type": "application", "name": "rcp-client", "version": "4.2.0"}},
"components": [
  {"type": "library", "name": "outer", "version": "1.0", "purl": "pkg:maven/g/outer@1.0",
   "components": [{"type": "library", "name": "inner", "purl": "pkg:maven/g/inner@2.0"}]}]}`)

	got := gate.Check(doc, all())
	if len(got.Findings) != 1 {
		t.Fatalf("Findings = %+v, want the nested component reported", got.Findings)
	}
	if got.Findings[0].Component != "pkg:maven/g/inner@2.0" {
		t.Fatalf("Component = %q, want the nested component's purl", got.Findings[0].Component)
	}
	if diff := cmp.Diff([]string{"version"}, got.Findings[0].Missing); diff != "" {
		t.Fatalf("Missing (-want +got):\n%s", diff)
	}
}

// A field that is present but whitespace is not identity: it would reach
// DependencyTrack as a whitespace project name (§5 step 4, §4.3d).
func TestWhitespaceIsNotIdentity(t *testing.T) {
	t.Run("subject", func(t *testing.T) {
		doc := load(t, `{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
"metadata": {"component": {"type": "application", "name": "  ", "version": "\t"}}}`)

		got := gate.Check(doc, all())
		if len(got.Findings) != 1 || !got.Findings[0].Subject {
			t.Fatalf("Findings = %+v, want a subject finding", got.Findings)
		}
		if diff := cmp.Diff([]string{"name", "version"}, got.Findings[0].Missing); diff != "" {
			t.Fatalf("Missing (-want +got):\n%s", diff)
		}
	})

	t.Run("component", func(t *testing.T) {
		doc := load(t, docWith(goodSubject,
			`{"type": "library", "name": " ", "version": "  ", "purl": "   "}`))

		got := gate.Check(doc, all())
		if len(got.Findings) != 1 {
			t.Fatalf("Findings = %+v, want one", got.Findings)
		}
		if diff := cmp.Diff([]string{"name", "version", "purl"}, got.Findings[0].Missing); diff != "" {
			t.Fatalf("Missing (-want +got):\n%s", diff)
		}
	})
}
