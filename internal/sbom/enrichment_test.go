package sbom_test

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/rebaze/rio/internal/enrichment"
)

func enrichmentFields(values map[string]string, replace ...string) *enrichment.Resolved {
	// Tests supply literal field values without depending on manifest resolution.
	fields := []enrichment.Field{}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := values[k]
		replacing := false
		for _, r := range replace {
			if r == k {
				replacing = true
			}
		}
		fields = append(fields, enrichment.Field{Field: k, Value: json.RawMessage(v), Source: "enrichment." + k, Replace: replacing})
	}
	return &enrichment.Resolved{Version: 1, Fields: fields}
}

const enrichmentDocument = `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"widget","version":"1.0","purl":"pkg:generic/widget@1.0","supplier":{"name":"Original supplier","url":["https://original.example"],"bom-ref":"supplier-id"}}}}`

func TestEnrichmentFailureDoesNotMutateDocument(t *testing.T) {
	d := load(t, []byte(enrichmentDocument))
	before, _ := d.Bytes()
	cfg := &enrichment.Resolved{Version: 1, Fields: []enrichment.Field{
		{Field: "producer.name", Value: json.RawMessage(`"SBOM team"`), Source: "enrichment.producer.name"},
		{Field: "subject.version", Value: json.RawMessage(`"2.0"`), Source: "enrichment.subject.version"},
	}}
	if _, err := d.Enrich(cfg, "rio.yaml", "digest"); err == nil {
		t.Fatal("expected conflict")
	}
	after, _ := d.Bytes()
	if !bytes.Equal(before, after) {
		t.Fatalf("failed enrichment modified document:\n%s", after)
	}
}

func TestEnrichmentOrganizationLeavesPreserveEvidence(t *testing.T) {
	d := load(t, []byte(enrichmentDocument))
	cfg := enrichmentFields(map[string]string{"subject.supplier.name": `"New supplier"`}, "subject.supplier.name")
	changes, err := d.Enrich(cfg, "rio.yaml", "digest")
	if err != nil {
		t.Fatal(err)
	}
	if len(changes.Changes) != 1 || changes.Changes[0].Before != "Original supplier" || changes.Changes[0].Target != "/metadata/component/supplier/name" {
		t.Fatal(changes)
	}
	b, _ := d.Bytes()
	root := tree(t, b).(map[string]any)
	supplier := root["metadata"].(map[string]any)["component"].(map[string]any)["supplier"]
	want := map[string]any{"name": "New supplier", "url": []any{"https://original.example"}, "bom-ref": "supplier-id"}
	if diff := cmp.Diff(want, supplier); diff != "" {
		t.Fatal(diff)
	}
}

func TestEnrichmentUsesExistingEquivalentReferenceAndLicense(t *testing.T) {
	src := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"licenses":[{"license":{"id":"CC0-1.0","url":"https://creativecommons.org/publicdomain/zero/1.0/"}}],"component":{"type":"application","name":"widget","externalReferences":[{"type":"security-contact","url":"mailto:security@example.com","comment":"Responsible team"},{"type":"vcs","url":"https://example.com/repo"}]}}}`
	d := load(t, []byte(src))
	before, _ := d.Bytes()
	cfg := enrichmentFields(map[string]string{"dataLicense": `"CC0-1.0"`, "subject.securityContact": `"mailto:security@example.com"`})
	changes, err := d.Enrich(cfg, "rio.yaml", "digest")
	if err != nil {
		t.Fatal(err)
	}
	if len(changes.Changes) != 0 {
		t.Fatal(changes)
	}
	after, _ := d.Bytes()
	if !bytes.Equal(before, after) {
		t.Fatalf("changed equivalent source metadata: %s", after)
	}
}

func TestEnrichmentReferenceReplacementPreservesOtherReferences(t *testing.T) {
	src := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"widget","externalReferences":[{"type":"security-contact","url":"mailto:old@example.com","comment":"Old evidence"},{"type":"vcs","url":"https://example.com/repo"},{"type":"security-contact","url":"https://old.example/security"}]}}}`
	d := load(t, []byte(src))
	cfg := enrichmentFields(map[string]string{"subject.securityContact": `"mailto:new@example.com"`})
	if _, err := d.Enrich(cfg, "rio.yaml", "digest"); err == nil {
		t.Fatal("conflicting reference accepted")
	}
	cfg.Fields[0].Replace = true
	rec, err := d.Enrich(cfg, "rio.yaml", "digest")
	if err != nil {
		t.Fatal(err)
	}
	want := []any{map[string]any{"type": "security-contact", "url": "mailto:new@example.com"}, map[string]any{"type": "vcs", "url": "https://example.com/repo"}}
	if diff := cmp.Diff(want, rec.Changes[0].After); diff != "" {
		t.Fatal(diff)
	}
	if len(rec.Changes[0].Before.([]any)) != 3 {
		t.Fatal("lost original reference evidence")
	}
}

func TestEnrichmentCycloneDX15Support(t *testing.T) {
	for _, tc := range []struct {
		field, value string
		allowed      bool
	}{
		{"subject.supplier.name", `"Supplier"`, true},
		{"subject.securityContact", `"mailto:security@example.com"`, true},
		{"dataLicense", `"CC0-1.0"`, true},
		{"producer.name", `"Producer"`, false},
		{"subject.manufacturer.name", `"Maker"`, false},
		{"subject.type", `"cryptographic-asset"`, false},
	} {
		t.Run(tc.field, func(t *testing.T) {
			d := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"name":"widget","type":"application"}}}`))
			_, err := d.Enrich(enrichmentFields(map[string]string{tc.field: tc.value}, tc.field), "rio.yaml", "digest")
			if tc.allowed && err != nil {
				t.Fatal(err)
			}
			if !tc.allowed && err == nil {
				t.Fatal("unsupported representation accepted")
			}
		})
	}
}

func TestEnrichmentRespectsLegacyOrganizationAssertions(t *testing.T) {
	for _, tc := range []struct{ field, legacy string }{
		{"subject.supplier.name", "supplier"}, {"subject.manufacturer.name", "manufacture"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			src := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"` + tc.legacy + `":{"name":"Existing organization","bom-ref":"org"},"component":{"type":"application","name":"widget"}}}`
			d := load(t, []byte(src))
			cfg := enrichmentFields(map[string]string{tc.field: `"New organization"`})
			if _, err := d.Enrich(cfg, "rio.yaml", "digest"); err == nil || !strings.Contains(err.Error(), tc.legacy) {
				t.Fatalf("legacy assertion not checked: %v", err)
			}
			cfg.Fields[0].Replace = true
			rec, err := d.Enrich(cfg, "rio.yaml", "digest")
			if err != nil {
				t.Fatal(err)
			}
			if len(rec.Changes) != 2 {
				t.Fatalf("expected native addition and legacy replacement: %+v", rec)
			}
			b, _ := d.Bytes()
			meta := tree(t, b).(map[string]any)["metadata"].(map[string]any)
			legacy := meta[tc.legacy].(map[string]any)
			if legacy["name"] != "New organization" || legacy["bom-ref"] != "org" {
				t.Fatal(legacy)
			}
		})
	}
}

func TestEnrichmentRetiresOldContactWhenNewContactAlreadyExists(t *testing.T) {
	src := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"widget","externalReferences":[{"type":"security-contact","url":"mailto:old@example.com"},{"type":"security-contact","url":"mailto:new@example.com","comment":"Keep evidence"},{"type":"vcs","url":"https://example.com/repo"}]}}}`
	d := load(t, []byte(src))
	cfg := enrichmentFields(map[string]string{"subject.securityContact": `"mailto:new@example.com"`})
	if _, err := d.Enrich(cfg, "rio.yaml", "digest"); err == nil {
		t.Fatal("mixed conflicting contacts accepted without replacement")
	}
	cfg.Fields[0].Replace = true
	rec, err := d.Enrich(cfg, "rio.yaml", "digest")
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Changes) != 1 {
		t.Fatalf("old contact was not retired: %+v", rec)
	}
	want := []any{map[string]any{"type": "security-contact", "url": "mailto:new@example.com", "comment": "Keep evidence"}, map[string]any{"type": "vcs", "url": "https://example.com/repo"}}
	if diff := cmp.Diff(want, rec.Changes[0].After); diff != "" {
		t.Fatal(diff)
	}
}
