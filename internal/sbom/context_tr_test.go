package sbom_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/buildcontext"
	"github.com/rebaze/rio/internal/sbom"
)

func boolPtr(b bool) *bool { return &b }

// trDistribution is a distribution carrying the four TR fields.
func trDistribution(name, sha256, sha512, url string, executable, archive, structured bool) buildcontext.Distribution {
	return buildcontext.Distribution{Name: name, SHA256: sha256, SHA512: sha512, URL: url,
		Executable: boolPtr(executable), Archive: boolPtr(archive), Structured: boolPtr(structured)}
}

var (
	trTarball = trDistribution("cart-api-1.4.0-linux-amd64.tar.gz", strings.Repeat("c", 64), strings.Repeat("e", 128),
		"https://downloads.example.org/cart-api/1.4.0/cart-api-1.4.0-linux-amd64.tar.gz", false, true, true)
	trExe = trDistribution("cart-api.exe", strings.Repeat("d", 64), strings.Repeat("f", 128), "", true, false, false)
)

// trSubjectDoc is a subject with a bom-ref, a creator and a concluded licence,
// one library, and a generator dependency entry for the subject.
const trSubjectDoc = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
"metadata":{"component":{"type":"application","bom-ref":"subject","name":"cart-api","version":"1.4.0",
"manufacturer":{"name":"Example GmbH","url":["https://example.org"]},
"licenses":[{"acknowledgement":"concluded","expression":"Apache-2.0"}]}},
"components":[{"type":"library","bom-ref":"zlib","name":"zlib","version":"1.3.1"}],
"dependencies":[{"ref":"subject","dependsOn":["zlib"]}]}`

// jsonTree decodes a JSON literal the way the raw layer does.
func jsonTree(t *testing.T, s string) any {
	t.Helper()
	return tree(t, []byte(s))
}

// asTree round-trips a Go value through JSON so it compares with jsonTree.
func asTree(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return tree(t, b)
}

func docTree(t *testing.T, d *sbom.Document) map[string]any {
	t.Helper()
	return tree(t, mustContextBytes(t, d)).(map[string]any)
}

func trResolved(level string, dists ...buildcontext.Distribution) *buildcontext.Resolved {
	var fields []buildcontext.Field
	if level != "" {
		fields = append(fields, contextField("level", level))
	}
	return withDistributions(contextResolved(fields...), dists...)
}

const tarballComponent = `{"type":"file","bom-ref":"rio:distribution:cart-api-1.4.0-linux-amd64.tar.gz",
"name":"cart-api-1.4.0-linux-amd64.tar.gz","version":"1.4.0",
"manufacturer":{"name":"Example GmbH","url":["https://example.org"]},
"licenses":[{"acknowledgement":"concluded","expression":"Apache-2.0"}],
"properties":[{"name":"bsi:component:filename","value":"cart-api-1.4.0-linux-amd64.tar.gz"},
{"name":"bsi:component:executable","value":"non-executable"},
{"name":"bsi:component:archive","value":"archive"},
{"name":"bsi:component:structured","value":"structured"}],
"externalReferences":[{"type":"distribution","url":"https://downloads.example.org/cart-api/1.4.0/cart-api-1.4.0-linux-amd64.tar.gz",
"hashes":[{"alg":"SHA-256","content":"` + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" + `"},
{"alg":"SHA-512","content":"` + "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" + `"}]}]}`

const exeComponent = `{"type":"file","bom-ref":"rio:distribution:cart-api.exe",
"name":"cart-api.exe","version":"1.4.0",
"manufacturer":{"name":"Example GmbH","url":["https://example.org"]},
"licenses":[{"acknowledgement":"concluded","expression":"Apache-2.0"}],
"properties":[{"name":"bsi:component:filename","value":"cart-api.exe"},
{"name":"bsi:component:executable","value":"executable"},
{"name":"bsi:component:archive","value":"no archive"},
{"name":"bsi:component:structured","value":"unstructured"}],
"externalReferences":[{"type":"distribution","url":"cart-api.exe",
"hashes":[{"alg":"SHA-256","content":"` + "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" + `"},
{"alg":"SHA-512","content":"` + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" + `"}]}]}`

const (
	tarballRef = "rio:distribution:cart-api-1.4.0-linux-amd64.tar.gz"
	exeRef     = "rio:distribution:cart-api.exe"
)

func TestApplyContextEmitsFileComponents(t *testing.T) {
	d := load(t, []byte(trSubjectDoc))
	rec, err := d.ApplyContext(trResolved("logical", trTarball, trExe))
	if err != nil {
		t.Fatal(err)
	}
	root := docTree(t, d)

	// The dependency component array is untouched; the files nest under the
	// subject they ship.
	if want := jsonTree(t, `[{"type":"library","bom-ref":"zlib","name":"zlib","version":"1.3.1"}]`); !reflect.DeepEqual(root["components"], want) {
		t.Fatalf("top-level components changed: %s", mustJSON(t, root["components"]))
	}
	wantFiles := jsonTree(t, `[`+tarballComponent+`,`+exeComponent+`]`)
	if got := subjectFiles(t, root); !reflect.DeepEqual(got, wantFiles) {
		t.Fatalf("subject components:\n got %s\nwant %s", mustJSON(t, got), mustJSON(t, wantFiles))
	}
	wantDeps := jsonTree(t, `[{"ref":"subject","dependsOn":["zlib","`+tarballRef+`","`+exeRef+`"]},
		{"ref":"`+tarballRef+`","dependsOn":[]},{"ref":"`+exeRef+`","dependsOn":[]}]`)
	if !reflect.DeepEqual(root["dependencies"], wantDeps) {
		t.Fatalf("dependencies:\n got %s\nwant %s", mustJSON(t, root["dependencies"]), mustJSON(t, wantDeps))
	}
	wantCompositions := jsonTree(t, `[{"aggregate":"complete","dependencies":["`+tarballRef+`","`+exeRef+`"]}]`)
	if !reflect.DeepEqual(root["compositions"], wantCompositions) {
		t.Fatalf("compositions: %s", mustJSON(t, root["compositions"]))
	}
	subject := root["metadata"].(map[string]any)["component"].(map[string]any)
	// The subject's own distribution references are exactly #171's: SHA-256 only.
	wantRefs := []any{distributionRef(trTarball.URL, trTarball.SHA256), distributionRef(trExe.Name, trExe.SHA256)}
	if !reflect.DeepEqual(subject["externalReferences"], wantRefs) {
		t.Fatalf("subject references: %s", mustJSON(t, subject["externalReferences"]))
	}
	wantProps := jsonTree(t, `[{"name":"rio:tr-03183-2:level","value":"logical"}]`)
	if !reflect.DeepEqual(subject["properties"], wantProps) {
		t.Fatalf("subject properties: %s", mustJSON(t, subject["properties"]))
	}

	wantChanges := []struct {
		field, target, before, after, selector string
	}{
		{"level", "context:/level", `null`, `"logical"`, "/artifacts/0/level"},
		{"distributions", "context:/distributions", `null`, mustJSON(t, []buildcontext.Distribution{trTarball, trExe}), "/artifacts/0/distributions"},
		{"distributions", "/metadata/component/externalReferences", `null`, mustJSON(t, wantRefs), "/artifacts/0/distributions"},
		{"distributions", "/metadata/component/components", `null`, `[` + tarballComponent + `,` + exeComponent + `]`, "/artifacts/0/distributions"},
		{"distributions", "/dependencies", `[{"ref":"subject","dependsOn":["zlib"]}]`,
			`[{"ref":"subject","dependsOn":["zlib","` + tarballRef + `","` + exeRef + `"]},{"ref":"` + tarballRef + `","dependsOn":[]},{"ref":"` + exeRef + `","dependsOn":[]}]`, "/artifacts/0/distributions"},
		{"distributions", "/compositions", `null`, `[{"aggregate":"complete","dependencies":["` + tarballRef + `","` + exeRef + `"]}]`, "/artifacts/0/distributions"},
		{"level", "/metadata/component/properties", `null`, `[{"name":"rio:tr-03183-2:level","value":"logical"}]`, "/artifacts/0/level"},
	}
	if len(rec.Changes) != len(wantChanges) {
		t.Fatalf("changes = %s", mustJSON(t, rec.Changes))
	}
	for i, want := range wantChanges {
		c := rec.Changes[i]
		if c.Field != want.field || c.Target != want.target || c.Selector != want.selector || c.Override ||
			!reflect.DeepEqual(asTree(t, c.Before), jsonTree(t, want.before)) || !reflect.DeepEqual(asTree(t, c.After), jsonTree(t, want.after)) {
			t.Fatalf("change %d = %s\nwant %+v", i, mustJSON(t, c), want)
		}
	}
	wantOwned := []string{
		"distribution:" + trTarball.Name, "distribution:" + trExe.Name,
		"distribution-component:" + trTarball.Name, "distribution-component:" + trExe.Name, "level",
	}
	if !reflect.DeepEqual(rec.OwnedReferences, wantOwned) {
		t.Fatalf("owned = %v, want %v", rec.OwnedReferences, wantOwned)
	}
	if stored := storedContext(t, d); !reflect.DeepEqual(stored.OwnedReferences, wantOwned) || stored.Effective.Level != "logical" ||
		len(stored.Effective.Distributions) != 2 || !stored.Effective.Distributions[0].Equal(trTarball) {
		t.Fatalf("stored record: %+v", stored)
	}
	// The written record is one rio itself accepts as a prior record.
	if _, err := loadContextOutput(t, d).ApplyContext(trResolved("logical", trTarball, trExe)); err != nil {
		t.Fatalf("own record rejected: %v", err)
	}
}

func TestApplyContextNoTRFieldsUnchanged(t *testing.T) {
	src := []byte(trSubjectDoc)
	d := load(t, src)
	rec, err := d.ApplyContext(withDistributions(contextResolved(), distA, distB))
	if err != nil {
		t.Fatal(err)
	}
	// rc1: the subject gains the SHA-256 references and the record, nothing else.
	want := tree(t, src).(map[string]any)
	meta := want["metadata"].(map[string]any)
	meta["component"].(map[string]any)["externalReferences"] = []any{distributionRef(distA.URL, distA.SHA256), distributionRef(distB.Name, distB.SHA256)}
	encoded, _ := json.Marshal(rec)
	meta["properties"] = []any{map[string]any{"name": "rebaze:normalize:context", "value": string(encoded)}}
	wantBytes, _ := json.Marshal(want)
	gotBytes, _ := json.Marshal(docTree(t, d))
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Fatalf("output:\n got %s\nwant %s", gotBytes, wantBytes)
	}
	if len(rec.Changes) != 2 || !reflect.DeepEqual(rec.OwnedReferences, []string{"distribution:" + distA.Name, "distribution:" + distB.Name}) {
		t.Fatalf("record: %s", encoded)
	}
	for _, s := range []string{"sha512", "executable", "archive", "structured", "distribution-component", "level"} {
		if strings.Contains(string(encoded), s) {
			t.Fatalf("rc1 record mentions %q: %s", s, encoded)
		}
	}
}

func TestApplyContextFileComponentsIdempotent(t *testing.T) {
	d := load(t, []byte(trSubjectDoc))
	if _, err := d.ApplyContext(trResolved("logical", trTarball, trExe)); err != nil {
		t.Fatal(err)
	}
	d = loadContextOutput(t, d)
	first := docTree(t, d)
	wantOwned := storedContext(t, d).OwnedReferences
	for i := 0; i < 2; i++ {
		before := withoutContextRecord(t, d)
		rec, err := d.ApplyContext(trResolved("logical", trTarball, trExe))
		if err != nil {
			t.Fatalf("reapply %d: %v", i, err)
		}
		if len(rec.Changes) != 0 {
			t.Fatalf("reapply %d changes: %s", i, mustJSON(t, rec.Changes))
		}
		if !reflect.DeepEqual(rec.OwnedReferences, wantOwned) {
			t.Fatalf("reapply %d owned = %v, want %v", i, rec.OwnedReferences, wantOwned)
		}
		if after := withoutContextRecord(t, d); !reflect.DeepEqual(before, after) {
			t.Fatalf("reapply %d changed the document:\n%s\n%s", i, mustJSON(t, before), mustJSON(t, after))
		}
		d = loadContextOutput(t, d)
	}
	root := docTree(t, d)
	for _, key := range []string{"components", "dependencies", "compositions"} {
		if !reflect.DeepEqual(root[key], first[key]) {
			t.Fatalf("%s changed on reapply: %s", key, mustJSON(t, root[key]))
		}
	}
	if n := len(root["components"].([]any)); n != 1 {
		t.Fatalf("top-level components = %d, want 1", n)
	}
	if n := len(subjectFiles(t, root)); n != 2 {
		t.Fatalf("subject components = %d, want 2", n)
	}
}

func TestApplyContextFileComponentChanged(t *testing.T) {
	t.Run("prior record, changed sha512", func(t *testing.T) {
		d := load(t, []byte(trSubjectDoc))
		if _, err := d.ApplyContext(trResolved("", trTarball, trExe)); err != nil {
			t.Fatal(err)
		}
		d = loadContextOutput(t, d)
		before := mustContextBytes(t, d)
		changed := trTarball
		changed.SHA512 = strings.Repeat("0", 128)
		_, err := d.ApplyContext(trResolved("", changed, trExe))
		want := fmt.Sprintf("distributions cannot be replaced: %q changed", trTarball.Name)
		if err == nil || !strings.HasSuffix(err.Error(), want) {
			t.Fatalf("want refusal ending %q: %v", want, err)
		}
		if !bytes.Equal(before, mustContextBytes(t, d)) {
			t.Fatal("refusal mutated document")
		}
	})
	t.Run("prior record, changed property", func(t *testing.T) {
		d := load(t, []byte(trSubjectDoc))
		if _, err := d.ApplyContext(trResolved("", trTarball)); err != nil {
			t.Fatal(err)
		}
		d = loadContextOutput(t, d)
		changed := trTarball
		changed.Executable = boolPtr(true)
		if _, err := d.ApplyContext(trResolved("", changed)); err == nil || !strings.Contains(err.Error(), "distributions cannot be replaced") {
			t.Fatalf("want refusal: %v", err)
		}
	})
	t.Run("prior record without TR fields", func(t *testing.T) {
		d := load(t, []byte(trSubjectDoc))
		plain := buildcontext.Distribution{Name: trTarball.Name, SHA256: trTarball.SHA256, URL: trTarball.URL}
		if _, err := d.ApplyContext(trResolved("", plain)); err != nil {
			t.Fatal(err)
		}
		d = loadContextOutput(t, d)
		if _, err := d.ApplyContext(trResolved("", trTarball)); err == nil || !strings.Contains(err.Error(), "distributions cannot be replaced") {
			t.Fatalf("want refusal: %v", err)
		}
	})
	t.Run("existing component with different content", func(t *testing.T) {
		root := tree(t, []byte(trSubjectDoc)).(map[string]any)
		existing := jsonTree(t, tarballComponent).(map[string]any)
		existing["version"] = "1.3.9"
		subjectOf(root)["components"] = []any{existing}
		src, _ := json.Marshal(root)
		d := load(t, src)
		before := mustContextBytes(t, d)
		_, err := d.ApplyContext(trResolved("", trTarball))
		if err == nil || !strings.HasSuffix(err.Error(), "distributions cannot be replaced: "+trTarball.Name) {
			t.Fatalf("want refusal naming %s: %v", trTarball.Name, err)
		}
		if !bytes.Equal(before, mustContextBytes(t, d)) {
			t.Fatal("refusal mutated document")
		}
	})
	t.Run("existing nested component with the bom-ref", func(t *testing.T) {
		root := tree(t, []byte(trSubjectDoc)).(map[string]any)
		zlib := root["components"].([]any)[0].(map[string]any)
		zlib["components"] = []any{jsonTree(t, tarballComponent)}
		src, _ := json.Marshal(root)
		d := load(t, src)
		if _, err := d.ApplyContext(trResolved("", trTarball)); err == nil || !strings.HasSuffix(err.Error(), "distributions cannot be replaced: "+trTarball.Name) {
			t.Fatalf("want refusal: %v", err)
		}
	})
	t.Run("existing top-level component with the bom-ref", func(t *testing.T) {
		root := tree(t, []byte(trSubjectDoc)).(map[string]any)
		root["components"] = append(root["components"].([]any), jsonTree(t, tarballComponent))
		src, _ := json.Marshal(root)
		d := load(t, src)
		if _, err := d.ApplyContext(trResolved("", trTarball)); err == nil || !strings.HasSuffix(err.Error(), "distributions cannot be replaced: "+trTarball.Name) {
			t.Fatalf("want refusal: %v", err)
		}
	})
	t.Run("existing identical component", func(t *testing.T) {
		root := tree(t, []byte(trSubjectDoc)).(map[string]any)
		subjectOf(root)["components"] = []any{jsonTree(t, tarballComponent)}
		src, _ := json.Marshal(root)
		d := load(t, src)
		rec, err := d.ApplyContext(trResolved("", trTarball))
		if err != nil {
			t.Fatal(err)
		}
		if n := len(subjectFiles(t, docTree(t, d))); n != 1 {
			t.Fatalf("subject components = %d, want 1 (kept, not duplicated)", n)
		}
		if containsOwned(rec.OwnedReferences, "distribution-component:"+trTarball.Name) {
			t.Fatalf("generator's component claimed as owned: %v", rec.OwnedReferences)
		}
		for _, c := range rec.Changes {
			if c.Target == "/metadata/component/components" {
				t.Fatalf("kept component recorded as a change: %s", mustJSON(t, c))
			}
		}
	})
}

func TestApplyContextSubjectWithoutBOMRef(t *testing.T) {
	root := tree(t, []byte(trSubjectDoc)).(map[string]any)
	delete(root["metadata"].(map[string]any)["component"].(map[string]any), "bom-ref")
	root["dependencies"] = []any{map[string]any{"ref": "zlib", "dependsOn": []any{}}}
	src, _ := json.Marshal(root)
	d := load(t, src)
	if _, err := d.ApplyContext(trResolved("", trTarball)); err != nil {
		t.Fatal(err)
	}
	out := docTree(t, d)
	if n := len(subjectFiles(t, out)); n != 1 {
		t.Fatalf("subject components = %d, want 1", n)
	}
	wantDeps := jsonTree(t, `[{"ref":"zlib","dependsOn":[]},{"ref":"`+tarballRef+`","dependsOn":[]}]`)
	if !reflect.DeepEqual(out["dependencies"], wantDeps) {
		t.Fatalf("dependencies: %s", mustJSON(t, out["dependencies"]))
	}
	if subject := out["metadata"].(map[string]any)["component"].(map[string]any); subject["bom-ref"] != nil {
		t.Fatalf("rio invented a subject bom-ref: %v", subject["bom-ref"])
	}
	wantCompositions := jsonTree(t, `[{"aggregate":"complete","dependencies":["`+tarballRef+`"]}]`)
	if !reflect.DeepEqual(out["compositions"], wantCompositions) {
		t.Fatalf("compositions: %s", mustJSON(t, out["compositions"]))
	}
	if err := sbom.Validate(mustContextBytes(t, d), "1.6"); err != nil {
		t.Fatal(err)
	}
}

func TestApplyContextSubjectWithoutCreatorOrLicence(t *testing.T) {
	root := tree(t, []byte(trSubjectDoc)).(map[string]any)
	subject := root["metadata"].(map[string]any)["component"].(map[string]any)
	delete(subject, "manufacturer")
	delete(subject, "licenses")
	delete(subject, "version")
	src, _ := json.Marshal(root)
	d := load(t, src)
	if _, err := d.ApplyContext(trResolved("", trTarball)); err != nil {
		t.Fatal(err)
	}
	file := subjectFiles(t, docTree(t, d))[0].(map[string]any)
	for _, key := range []string{"manufacturer", "licenses", "version"} {
		if _, ok := file[key]; ok {
			t.Fatalf("file component has %s the subject lacks: %s", key, mustJSON(t, file))
		}
	}
}

func TestApplyContextCopiesWithoutBOMRefs(t *testing.T) {
	root := tree(t, []byte(trSubjectDoc)).(map[string]any)
	subject := root["metadata"].(map[string]any)["component"].(map[string]any)
	subject["manufacturer"] = jsonTree(t, `{"bom-ref":"maker","name":"Example GmbH","contact":[{"bom-ref":"maker-contact","email":"sbom@example.org"}]}`)
	subject["licenses"] = jsonTree(t, `[{"license":{"bom-ref":"lic","id":"Apache-2.0","acknowledgement":"concluded"}}]`)
	src, _ := json.Marshal(root)
	d := load(t, src)
	if _, err := d.ApplyContext(trResolved("", trTarball, trExe)); err != nil {
		t.Fatal(err)
	}
	out := docTree(t, d)
	file := subjectFiles(t, out)[0].(map[string]any)
	if !reflect.DeepEqual(file["manufacturer"], jsonTree(t, `{"name":"Example GmbH","contact":[{"email":"sbom@example.org"}]}`)) ||
		!reflect.DeepEqual(file["licenses"], jsonTree(t, `[{"license":{"id":"Apache-2.0","acknowledgement":"concluded"}}]`)) {
		t.Fatalf("copies keep bom-refs: %s", mustJSON(t, file))
	}
	// The subject keeps its own.
	if out["metadata"].(map[string]any)["component"].(map[string]any)["manufacturer"].(map[string]any)["bom-ref"] != "maker" {
		t.Fatal("subject manufacturer changed")
	}
	if err := sbom.Validate(mustContextBytes(t, d), "1.6"); err != nil {
		t.Fatal(err)
	}
}

func TestApplyContextLevel(t *testing.T) {
	t.Run("written and owned", func(t *testing.T) {
		d := load(t, []byte(trSubjectDoc))
		rec, err := d.ApplyContext(trResolved("assembled"))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(rec.OwnedReferences, []string{"level"}) {
			t.Fatalf("owned = %v", rec.OwnedReferences)
		}
		d = loadContextOutput(t, d)
		before := withoutContextRecord(t, d)
		rec, err = d.ApplyContext(trResolved("assembled"))
		if err != nil {
			t.Fatal(err)
		}
		if len(rec.Changes) != 0 || !reflect.DeepEqual(rec.OwnedReferences, []string{"level"}) || !reflect.DeepEqual(before, withoutContextRecord(t, d)) {
			t.Fatalf("reapply: %s", mustJSON(t, rec))
		}
	})
	t.Run("same value in the SBOM is kept", func(t *testing.T) {
		root := tree(t, []byte(trSubjectDoc)).(map[string]any)
		props := jsonTree(t, `[{"name":"example","value":"x"},{"name":"rio:tr-03183-2:level","value":"logical"}]`)
		root["metadata"].(map[string]any)["component"].(map[string]any)["properties"] = props
		src, _ := json.Marshal(root)
		d := load(t, src)
		rec, err := d.ApplyContext(trResolved("logical"))
		if err != nil {
			t.Fatal(err)
		}
		got := docTree(t, d)["metadata"].(map[string]any)["component"].(map[string]any)["properties"]
		if !reflect.DeepEqual(got, props) {
			t.Fatalf("properties: %s", mustJSON(t, got))
		}
		if len(rec.OwnedReferences) != 0 {
			t.Fatalf("generator's level claimed as owned: %v", rec.OwnedReferences)
		}
		if len(rec.Changes) != 1 || rec.Changes[0].Target != "context:/level" {
			t.Fatalf("changes: %s", mustJSON(t, rec.Changes))
		}
	})
}

func TestApplyContextLevelConflict(t *testing.T) {
	t.Run("SBOM has another value", func(t *testing.T) {
		root := tree(t, []byte(trSubjectDoc)).(map[string]any)
		root["metadata"].(map[string]any)["component"].(map[string]any)["properties"] = jsonTree(t, `[{"name":"rio:tr-03183-2:level","value":"identified"}]`)
		src, _ := json.Marshal(root)
		d := load(t, src)
		before := mustContextBytes(t, d)
		_, err := d.ApplyContext(trResolved("logical", trTarball))
		want := `context level "logical" conflicts with the SBOM's rio:tr-03183-2:level "identified"; the level cannot be replaced`
		if err == nil || err.Error() != want {
			t.Fatalf("error = %v, want %q", err, want)
		}
		if !bytes.Equal(before, mustContextBytes(t, d)) {
			t.Fatal("refusal mutated document")
		}
	})
	t.Run("prior record has another value", func(t *testing.T) {
		d := load(t, []byte(trSubjectDoc))
		if _, err := d.ApplyContext(trResolved("logical")); err != nil {
			t.Fatal(err)
		}
		d = loadContextOutput(t, d)
		cfg := trResolved("identified")
		_, err := d.ApplyContext(cfg)
		want := `context level "identified" conflicts with the SBOM's rio:tr-03183-2:level "logical"; the level cannot be replaced`
		if err == nil || err.Error() != want {
			t.Fatalf("error = %v, want %q", err, want)
		}
	})
	t.Run("prior record level removed", func(t *testing.T) {
		d := load(t, []byte(trSubjectDoc))
		if _, err := d.ApplyContext(trResolved("logical")); err != nil {
			t.Fatal(err)
		}
		d = loadContextOutput(t, d)
		if _, err := d.ApplyContext(trResolved("")); err == nil || !strings.Contains(err.Error(), "level") {
			t.Fatalf("removal accepted: %v", err)
		}
	})
}

func TestApplyContextOutputValidates(t *testing.T) {
	for _, src := range []string{trSubjectDoc, `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"app","version":"1"}}}`} {
		d := load(t, []byte(src))
		if _, err := d.ApplyContext(trResolved("logical", trTarball, trExe)); err != nil {
			t.Fatal(err)
		}
		if err := sbom.Validate(mustContextBytes(t, d), "1.6"); err != nil {
			t.Fatalf("output is not valid 1.6: %v\n%s", err, mustContextBytes(t, d))
		}
	}
}

func TestContextRejectsMalformedPriorFileComponentRecord(t *testing.T) {
	d := load(t, []byte(trSubjectDoc))
	if _, err := d.ApplyContext(trResolved("logical", trTarball)); err != nil {
		t.Fatal(err)
	}
	changeAt := func(r map[string]any, target string) map[string]any {
		for _, raw := range r["changes"].([]any) {
			if c := raw.(map[string]any); c["target"] == target {
				return c
			}
		}
		t.Fatalf("no change for %s", target)
		return nil
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"unknown owned component", func(r map[string]any) {
			r["ownedReferences"] = []any{"distribution-component:other"}
		}},
		{"owned level without level", func(r map[string]any) {
			delete(r["effective"].(map[string]any), "level")
			r["changes"] = []any{}
			r["ownedReferences"] = []any{"level"}
		}},
		{"partial TR claim", func(r map[string]any) {
			delete(changeAt(r, "context:/distributions")["after"].([]any)[0].(map[string]any), "archive")
		}},
		{"bad sha512 claim", func(r map[string]any) {
			changeAt(r, "context:/distributions")["after"].([]any)[0].(map[string]any)["sha512"] = "bad"
		}},
		{"components with a prior value", func(r map[string]any) {
			c := changeAt(r, "/metadata/component/components")
			c["before"] = c["after"]
		}},
		{"components not objects", func(r map[string]any) { changeAt(r, "/metadata/component/components")["after"] = []any{"x"} }},
		{"dependency without ref", func(r map[string]any) {
			changeAt(r, "/dependencies")["after"] = []any{map[string]any{"dependsOn": []any{}}}
		}},
		{"composition without aggregate", func(r map[string]any) {
			changeAt(r, "/compositions")["after"] = []any{map[string]any{"dependencies": []any{tarballRef}}}
		}},
		{"level property change for another field", func(r map[string]any) {
			changeAt(r, "/metadata/component/properties")["field"] = "lifecycle"
		}},
		{"level property not a property", func(r map[string]any) {
			changeAt(r, "/metadata/component/properties")["after"] = []any{map[string]any{"value": "logical"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := docTree(t, d)
			var prop map[string]any
			for _, raw := range root["metadata"].(map[string]any)["properties"].([]any) {
				if p := raw.(map[string]any); p["name"] == "rebaze:normalize:context" {
					prop = p
				}
			}
			var record map[string]any
			if err := json.Unmarshal([]byte(prop["value"].(string)), &record); err != nil {
				t.Fatal(err)
			}
			tc.mutate(record)
			encoded, _ := json.Marshal(record)
			prop["value"] = string(encoded)
			data, _ := json.Marshal(root)
			bad := load(t, data)
			if _, err := bad.ApplyContext(trResolved("logical", trTarball)); err == nil || !strings.Contains(err.Error(), "malformed prior") {
				t.Fatalf("malformed prior record accepted: %v", err)
			}
		})
	}
}

// withoutContextRecord is the document minus rio's context record, whose
// changes list empties when an unchanged snapshot is reapplied.
func withoutContextRecord(t *testing.T, d *sbom.Document) map[string]any {
	t.Helper()
	root := docTree(t, d)
	meta := root["metadata"].(map[string]any)
	var kept []any
	for _, raw := range meta["properties"].([]any) {
		if raw.(map[string]any)["name"] != "rebaze:normalize:context" {
			kept = append(kept, raw)
		}
	}
	meta["properties"] = kept
	return root
}

func subjectOf(root map[string]any) map[string]any {
	return root["metadata"].(map[string]any)["component"].(map[string]any)
}

// subjectFiles is metadata.component.components, where rio nests the TR file
// components.
func subjectFiles(t *testing.T, root map[string]any) []any {
	t.Helper()
	files, ok := subjectOf(root)["components"].([]any)
	if !ok {
		t.Fatalf("subject has no components: %s", mustJSON(t, subjectOf(root)))
	}
	return files
}

func containsOwned(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
