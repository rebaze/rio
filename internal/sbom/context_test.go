package sbom_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/buildcontext"
	"github.com/rebaze/rio/internal/sbom"
)

func contextResolved(fields ...buildcontext.Field) *buildcontext.Resolved {
	a := buildcontext.Artifact{ID: "app", SBOM: buildcontext.Digest{SHA256: strings.Repeat("a", 64)}}
	for _, f := range fields {
		v := f.Value
		switch f.Name {
		case "source.repository":
			if a.Source == nil {
				a.Source = &buildcontext.Source{}
			}
			a.Source.Repository = &v
		case "source.revision":
			if a.Source == nil {
				a.Source = &buildcontext.Source{}
			}
			a.Source.Revision = &v
		case "source.workspace":
			if a.Source == nil {
				a.Source = &buildcontext.Source{}
			}
			a.Source.Workspace = &v
		case "build.url":
			if a.Build == nil {
				a.Build = &buildcontext.Build{}
			}
			a.Build.URL = &v
		case "build.id":
			if a.Build == nil {
				a.Build = &buildcontext.Build{}
			}
			a.Build.ID = &v
		case "lifecycle":
			a.Lifecycle = &v
		}
	}
	return &buildcontext.Resolved{File: buildcontext.FileRef{Path: "context.json", SHA256: strings.Repeat("b", 64)}, Selector: "/artifacts/0", Artifact: a, Fields: fields}
}

func contextField(name, value string) buildcontext.Field {
	return buildcontext.Field{Name: name, Value: value, Selector: "/artifacts/0/" + strings.ReplaceAll(name, ".", "/")}
}

func TestContextAddsClaimsAndNativeReferencesWithoutChangingOtherEvidence(t *testing.T) {
	src := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"timestamp":"2025-01-01T00:00:00Z","tools":{"services":[{"name":"generator"}]},"component":{"type":"application","name":"app","externalReferences":[{"type":"vcs","url":"https://code.example/app","comment":"signed"},{"type":"website","url":"https://example.org"}]}},"components":[{"type":"library","name":"dependency"}]}`
	d := load(t, []byte(src))
	cfg := contextResolved(contextField("source.repository", "https://code.example/app"), contextField("source.revision", strings.Repeat("1", 40)), contextField("build.url", "https://ci.example/run/1"))
	rec, err := d.ApplyContext(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Version != 1 || rec.Assertion != "producer" || rec.File.Path != "context.json" || rec.Effective.Source == nil || *rec.Effective.Source.Revision != strings.Repeat("1", 40) {
		t.Fatalf("record: %+v", rec)
	}
	b, _ := d.Bytes()
	root := tree(t, b).(map[string]any)
	meta := root["metadata"].(map[string]any)
	if meta["timestamp"] != "2025-01-01T00:00:00Z" || root["components"].([]any)[0].(map[string]any)["name"] != "dependency" {
		t.Fatal("unrelated evidence changed")
	}
	refs := meta["component"].(map[string]any)["externalReferences"].([]any)
	if len(refs) != 3 || refs[0].(map[string]any)["comment"] != "signed" {
		t.Fatalf("references: %v", refs)
	}
	props := meta["properties"].([]any)
	if len(props) != 1 {
		t.Fatalf("properties: %v", props)
	}
	var stored sbom.ContextRecord
	if err := json.Unmarshal([]byte(props[0].(map[string]any)["value"].(string)), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Effective.Source == nil || *stored.Effective.Source.Revision != *rec.Effective.Source.Revision {
		t.Fatalf("stored record: %+v", stored)
	}
}

func TestContextConflictIsAtomicAndReplaceIsAudited(t *testing.T) {
	d := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"app","externalReferences":[{"type":"vcs","url":"https://old.example/repo"}]}}}`))
	before, _ := d.Bytes()
	cfg := contextResolved(contextField("source.repository", "https://new.example/repo"))
	if _, err := d.ApplyContext(cfg); err == nil || !strings.Contains(err.Error(), "context.replace") {
		t.Fatalf("want context conflict: %v", err)
	}
	after, _ := d.Bytes()
	if !bytes.Equal(before, after) {
		t.Fatal("failed context mutated document")
	}
	cfg.Replace = []string{"source.repository"}
	rec, err := d.ApplyContext(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Changes) != 2 || !rec.Changes[1].Override || rec.Changes[1].Target != "/metadata/component/externalReferences" {
		t.Fatalf("changes: %+v", rec.Changes)
	}
}

func TestContextWithoutSubjectFailsUsefully(t *testing.T) {
	d := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`))
	_, err := d.ApplyContext(contextResolved(contextField("source.revision", strings.Repeat("1", 40))))
	if err == nil || !strings.Contains(err.Error(), "metadata.component") {
		t.Fatalf("missing subject: %v", err)
	}
}

func TestContextLifecycleRejectsKnownMismatchAndPreservesCustom(t *testing.T) {
	for _, tc := range []struct {
		native string
		fail   bool
	}{{`[{"phase":"design"}]`, true}, {`[{"phase":"build"},{"name":"custom"}]`, false}, {`[{"name":"custom"}]`, false}, {`[]`, false}} {
		d := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"app"},"lifecycles":`+tc.native+`}}`))
		before, _ := d.Bytes()
		_, err := d.ApplyContext(contextResolved(contextField("lifecycle", "build")))
		if (err != nil) != tc.fail {
			t.Fatalf("native %s: %v", tc.native, err)
		}
		if tc.fail {
			after, _ := d.Bytes()
			if !bytes.Equal(before, after) {
				t.Fatal("failure mutated document")
			}
		}
		if !tc.fail {
			after, _ := d.Bytes()
			got := tree(t, after).(map[string]any)["metadata"].(map[string]any)["lifecycles"]
			var want any
			if err := json.Unmarshal([]byte(tc.native), &want); err != nil {
				t.Fatal(err)
			}
			if len(want.([]any)) == 0 {
				want = []any{map[string]any{"phase": "build"}}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("native lifecycle %s changed to %v", tc.native, got)
			}
		}
	}
}

func TestPriorLifecycleChangeOrRemovalIsNotReplaceable(t *testing.T) {
	for _, fields := range [][]buildcontext.Field{{contextField("lifecycle", "design")}, nil} {
		d := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"app"}}}`))
		if _, err := d.ApplyContext(contextResolved(contextField("lifecycle", "build"))); err != nil {
			t.Fatal(err)
		}
		d = loadContextOutput(t, d)
		_, err := d.ApplyContext(contextResolved(fields...))
		if err == nil || !strings.Contains(err.Error(), "cannot be changed or removed") || strings.Contains(err.Error(), "context.replace") {
			t.Fatalf("lifecycle diagnostic: %v", err)
		}
	}
}

func TestContextRejectsMalformedPriorRecordAtomically(t *testing.T) {
	base := `{"version":1,"file":{"path":"old.json","sha256":"` + strings.Repeat("b", 64) + `"},"selector":"/artifacts/0","effective":{"id":"app","sbom":{"sha256":"` + strings.Repeat("a", 64) + `"},"build":{"id":"42"}},"defaulted":[],"changes":[],"assertion":"producer"}`
	for _, tc := range []struct{ name, record string }{
		{"duplicate outer", strings.Replace(base, `"version":1,`, `"version":1,"version":1,`, 1)},
		{"contradictory effective", strings.Replace(base, `"build":{"id":"42"}`, `"build":{"id":"42"},"build":{"id":"43"}`, 1)},
		{"duplicate effective member", strings.Replace(base, `"effective":{"id":"app","sbom":{"sha256":"`+strings.Repeat("a", 64)+`"},"build":{"id":"42"}}`, `"effective":{"id":"app","sbom":{"sha256":"`+strings.Repeat("a", 64)+`"},"build":{"id":"42"}},"effective":{"id":"app","sbom":{"sha256":"`+strings.Repeat("a", 64)+`"},"build":{"id":"43"}}`, 1)},
		{"duplicate nested file", strings.Replace(base, `"path":"old.json",`, `"path":"old.json","path":"other.json",`, 1)},
		{"null change", strings.Replace(base, `"changes":[]`, `"changes":[null]`, 1)},
		{"incomplete change", strings.Replace(base, `"changes":[]`, `"changes":[{"field":"build.id","target":"context:/build/id"}]`, 1)},
		{"missing change before", strings.Replace(base, `"changes":[]`, `"changes":[{"field":"build.id","target":"context:/build/id","after":"42","selector":"/artifacts/0/build/id","override":false}]`, 1)},
		{"unknown change field", strings.Replace(base, `"changes":[]`, `"changes":[{"field":"build.secret","target":"context:/build/secret","before":null,"after":"value","selector":"/artifacts/0/build/secret","override":false}]`, 1)},
		{"wrong logical before type", strings.Replace(base, `"changes":[]`, `"changes":[{"field":"build.id","target":"context:/build/id","before":["old"],"after":"42","selector":"/artifacts/0/build/id","override":true}]`, 1)},
		{"wrong entry selector", strings.Replace(base, `"changes":[]`, `"changes":[{"field":"build.id","target":"context:/build/id","before":null,"after":"42","selector":"/artifacts/00/build/id","override":false}]`, 1)},
		{"missing file path", strings.Replace(base, `"path":"old.json",`, "", 1)},
		{"source missing workspace", strings.Replace(base, `"build":{"id":"42"}`, `"source":{"revision":"`+strings.Repeat("1", 40)+`"},"build":{"id":"42"}`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			property, _ := json.Marshal(tc.record)
			d := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"app"},"properties":[{"name":"rebaze:normalize:context","value":`+string(property)+`}]}}`))
			before, _ := d.Bytes()
			newID := "42"
			if tc.name == "contradictory effective" || tc.name == "duplicate effective member" {
				newID = "43"
			}
			fields := []buildcontext.Field{contextField("build.id", newID)}
			if tc.name == "source missing workspace" {
				fields = append(fields, contextField("source.revision", strings.Repeat("1", 40)))
			}
			_, err := d.ApplyContext(contextResolved(fields...))
			if err == nil {
				t.Fatal("malformed prior record accepted")
			}
			after, _ := d.Bytes()
			if !bytes.Equal(before, after) {
				t.Fatal("failed context changed document")
			}
		})
	}
}

func TestContextPriorClaimsNeedExplicitRemovalAndDoNotLeakIntoNewSnapshot(t *testing.T) {
	d := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"app"}}}`))
	old := contextResolved(contextField("source.revision", strings.Repeat("1", 40)), contextField("source.workspace", "clean"), contextField("build.id", "42"))
	if _, err := d.ApplyContext(old); err != nil {
		t.Fatal(err)
	}
	d = loadContextOutput(t, d)
	before, _ := d.Bytes()
	next := contextResolved(contextField("source.revision", strings.Repeat("2", 40)), buildcontext.Field{Name: "source.workspace", Value: "unknown", Selector: "/artifacts/0/source", Defaulted: true})
	next.Defaulted = []string{"source.workspace"}
	if _, err := d.ApplyContext(next); err == nil || !strings.Contains(err.Error(), "context.replace") {
		t.Fatalf("want override requirement: %v", err)
	}
	after, _ := d.Bytes()
	if !bytes.Equal(before, after) {
		t.Fatal("conflict mutated document")
	}
	next.Replace = []string{"source.revision", "source.workspace", "build.id"}
	rec, err := d.ApplyContext(next)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Effective.Build != nil || *rec.Effective.Source.Workspace != "unknown" || len(rec.Defaulted) != 1 {
		t.Fatalf("stale claims survived: %+v", rec)
	}
	removed := false
	for _, change := range rec.Changes {
		if change.Field == "build.id" {
			removed = change.Before == "42" && change.After == nil && change.Selector == "/artifacts/0" && change.Override
		}
	}
	if !removed {
		t.Fatalf("missing removal audit: %+v", rec.Changes)
	}
}

func TestContextReplacingBuildURLCannotInheritOldBuildID(t *testing.T) {
	d := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"app"}}}`))
	old := contextResolved(contextField("build.url", "https://ci.example/old"), contextField("build.id", "42"))
	if _, err := d.ApplyContext(old); err != nil {
		t.Fatal(err)
	}
	d = loadContextOutput(t, d)
	next := contextResolved(contextField("build.url", "https://ci.example/new"))
	next.Replace = []string{"build.url"}
	if _, err := d.ApplyContext(next); err == nil || !strings.Contains(err.Error(), "build.id") {
		t.Fatalf("omitted ID accepted: %v", err)
	}
	next.Replace = []string{"build.url", "build.id"}
	rec, err := d.ApplyContext(next)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Effective.Build.ID != nil {
		t.Fatal("old build ID inherited")
	}
	seen := false
	for _, c := range rec.Changes {
		if c.Field == "build.url" && c.Target == "/metadata/component/externalReferences" {
			seen = c.Override
		}
	}
	if !seen {
		t.Fatalf("native build URL replacement not audited: %+v", rec.Changes)
	}
}

func TestContextRejectsContradictoryOrUnsupportedPriorProperties(t *testing.T) {
	base := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"app"}}}`))
	if _, err := base.ApplyContext(contextResolved(contextField("build.id", "42"))); err != nil {
		t.Fatal(err)
	}
	b, _ := base.Bytes()
	root := tree(t, b).(map[string]any)
	meta := root["metadata"].(map[string]any)
	props := meta["properties"].([]any)
	original := props[0].(map[string]any)
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"bad version", func(r map[string]any) { r["version"] = float64(2) }},
		{"bad effective", func(r map[string]any) { r["effective"].(map[string]any)["build"].(map[string]any)["id"] = nil }},
		{"bad file digest", func(r map[string]any) { r["file"].(map[string]any)["sha256"] = "bad" }},
		{"bogus default", func(r map[string]any) { r["defaulted"] = []any{"build.id"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var record map[string]any
			if err := json.Unmarshal([]byte(original["value"].(string)), &record); err != nil {
				t.Fatal(err)
			}
			tc.mutate(record)
			encoded, _ := json.Marshal(record)
			meta["properties"] = []any{map[string]any{"name": "rebaze:normalize:context", "value": string(encoded)}}
			docBytes, _ := json.Marshal(root)
			d := load(t, docBytes)
			if _, err := d.ApplyContext(contextResolved(contextField("build.id", "42"))); err == nil {
				t.Fatal("invalid prior record accepted")
			}
		})
	}
	meta["properties"] = []any{original, map[string]any{"name": "rebaze:normalize:context", "value": strings.Replace(original["value"].(string), "42", "43", 1)}}
	docBytes, _ := json.Marshal(root)
	d := load(t, docBytes)
	if _, err := d.ApplyContext(contextResolved(contextField("build.id", "42"))); err == nil || !strings.Contains(err.Error(), "contradictory") {
		t.Fatalf("duplicate properties: %v", err)
	}
	meta["properties"] = []any{original, original, map[string]any{"name": "other", "value": "keep"}}
	docBytes, _ = json.Marshal(root)
	d = load(t, docBytes)
	if _, err := d.ApplyContext(contextResolved(contextField("build.id", "42"))); err != nil {
		t.Fatal(err)
	}
	out, _ := d.Bytes()
	got := tree(t, out).(map[string]any)["metadata"].(map[string]any)["properties"].([]any)
	if len(got) != 2 || got[0].(map[string]any)["name"] != "other" {
		t.Fatalf("identical records not deduplicated: %v", got)
	}
}

func loadContextOutput(t *testing.T, d *sbom.Document) *sbom.Document {
	t.Helper()
	b, err := d.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return load(t, b)
}
