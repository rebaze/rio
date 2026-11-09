package manifest_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/rebaze/rio/internal/manifest"
)

func TestEnrichmentMergeAndSource(t *testing.T) {
	m, err := manifest.Load(write(t, `version: 1
enrichment:
  subject:
    name: Shared
    group: com.example
    manufacturer:
      name: Maker
      url: [https://maker.example]
  producer:
    name: Producer
  dataLicense: CC0-1.0
  replace: [subject.name]
artifacts:
  - id: a
    sbom: a.json
    enrichment:
      subject:
        name: Local
        manufacturer:
          name: Local Maker
  - id: b
    sbom: b.json
    enrichment:
      replace: []
`))
	if err != nil {
		t.Fatal(err)
	}
	// Assert through JSON so this test fails on the missing behavior before the API exists.
	b, _ := json.Marshal(m.Artifacts)
	var artifacts []map[string]json.RawMessage
	_ = json.Unmarshal(b, &artifacts)
	if len(artifacts[0]["Enrichment"]) == 0 {
		t.Fatalf("missing resolved enrichment: %s", b)
	}
	var resolved struct {
		Version int
		Fields  []struct {
			Field   string
			Value   json.RawMessage
			Source  string
			Replace bool
		}
	}
	if err := json.Unmarshal(artifacts[0]["Enrichment"], &resolved); err != nil {
		t.Fatal(err)
	}
	if resolved.Version != 1 || len(resolved.Fields) != 6 {
		t.Fatalf("resolved = %+v", resolved)
	}
	last := ""
	for _, f := range resolved.Fields {
		if f.Field <= last {
			t.Fatal("fields not sorted")
		}
		last = f.Field
		switch f.Field {
		case "subject.name":
			if string(f.Value) != `"Local"` || f.Source != "artifacts[0].enrichment.subject.name" || !f.Replace {
				t.Fatalf("local field = %+v", f)
			}
		case "subject.manufacturer.url":
			if string(f.Value) != `["https://maker.example"]` || f.Source != "enrichment.subject.manufacturer.url" {
				t.Fatalf("inherited leaf = %+v", f)
			}
		}
	}
	if err := json.Unmarshal(artifacts[1]["Enrichment"], &resolved); err != nil {
		t.Fatal(err)
	}
	for _, f := range resolved.Fields {
		if f.Replace {
			t.Fatalf("replace [] did not clear defaults: %+v", f)
		}
	}
}

func TestEnrichmentRejectsInvalidConfiguration(t *testing.T) {
	cases := []struct{ name, block, want string }{
		{"typo", "subject: {naem: App}", "unknown key"},
		{"blank", `subject: {name: '   '}`, "subject.name"},
		{"number", "subject: {version: 1.2}", "string"},
		{"boolean", "producer: {name: true}", "string"},
		{"type", "subject: {type: banana}", "subject.type"},
		{"url", "subject: {website: relative/path}", "subject.website"},
		{"credentials", "producer: {url: ['https://user:pass@example.com']}", "producer.url"},
		{"email", "producer: {contact: [{email: invalid}]}", "producer.contact"},
		{"empty contact", "producer: {contact: [{}]}", "producer.contact"},
		{"security", "subject: {securityContact: 'mailto:invalid'}", "subject.securityContact"},
		{"purl", "subject: {purl: invalid}", "subject.purl"},
		{"replace unknown", "replace: [subject.nam]", "replace"},
		{"replace absent", "replace: [subject.name]", "replace"},
		{"replace duplicate", "subject: {name: App}\n  replace: [subject.name, subject.name]", "replace"},
		{"license expression", "dataLicense: MIT OR Apache-2.0", "dataLicense"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := manifest.Load(write(t, "version: 1\nenrichment:\n  "+tt.block+"\nartifacts:\n  - id: a\n    sbom: a.json\n"))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v; want %q", err, tt.want)
			}
		})
	}
}

func TestEnrichmentRejectsInvalidShapesWithManifestFields(t *testing.T) {
	for _, tt := range []struct{ block, field string }{
		{"subject: text", "enrichment.subject"},
		{"producer: text", "enrichment.producer"},
		{"producer: {contact: text}", "enrichment.producer.contact"},
		{"producer: {url: text}", "enrichment.producer.url"},
	} {
		_, err := manifest.Load(write(t, "version: 1\nenrichment:\n  "+tt.block+"\nartifacts: [{id: a, sbom: a.json}]\n"))
		if err == nil || !strings.Contains(err.Error(), tt.field) || strings.Contains(err.Error(), "enrichment.Organization") || strings.Contains(err.Error(), "enrichment.Contact") || strings.Contains(err.Error(), "enrichment.Subject") {
			t.Errorf("error=%v, want manifest field %s", err, tt.field)
		}
	}
}

func TestEnrichmentRejectsUnknownSPDXIdentifier(t *testing.T) {
	_, err := manifest.Load(write(t, "version: 1\nenrichment: {dataLicense: Definitely-Not-A-License}\nartifacts: [{id: a, sbom: a.json}]\n"))
	if err == nil || !strings.Contains(err.Error(), "dataLicense") {
		t.Fatalf("error=%v, want dataLicense validation", err)
	}
}

// A data licence is a licence; an SPDX exception ID names none.
func TestEnrichmentRejectsSPDXExceptionAsDataLicense(t *testing.T) {
	_, err := manifest.Load(write(t, "version: 1\nenrichment: {dataLicense: LLVM-exception}\nartifacts: [{id: a, sbom: a.json}]\n"))
	if err == nil || !strings.Contains(err.Error(), "dataLicense") {
		t.Fatalf("error=%v, want dataLicense validation", err)
	}
}

func TestEnrichmentStrictStringsThroughYAMLMerges(t *testing.T) {
	for _, value := range []string{"1.2", "true", "null"} {
		for _, tt := range []struct{ name, body, path string }{
			{"root", "version: 1\n<<: &defaults\n  enrichment:\n    subject: {version: " + value + "}\nartifacts: [{id: a, sbom: input.json}]\n", "enrichment.subject.version"},
			{"artifact", "version: 1\nartifacts:\n  - id: a\n    sbom: input.json\n    <<: &defaults\n      enrichment:\n        subject: {version: " + value + "}\n", "artifacts[0].enrichment.subject.version"},
			{"root sequence", "version: 1\n<<: [{enrichment: {subject: {version: " + value + "}}}]\nartifacts: [{id: a, sbom: input.json}]\n", "enrichment.subject.version"},
			{"scalar alias", "version: 1\nartifacts:\n  - id: a\n    sbom: &scalar " + value + "\n    <<: {enrichment: {subject: {version: *scalar}}}\n", "artifacts[0].enrichment.subject.version"},
		} {
			t.Run(tt.name+"/"+value, func(t *testing.T) {
				_, err := manifest.Load(write(t, tt.body))
				if err == nil || !strings.Contains(err.Error(), tt.path) || !strings.Contains(err.Error(), "must be a string") {
					t.Fatalf("error = %v; want strict scalar at %s", err, tt.path)
				}
			})
		}
	}
}

func TestEnrichmentYAMLMergesPreserveStringValues(t *testing.T) {
	m, err := manifest.Load(write(t, `version: 1
<<: [{enrichment: {subject: {version: '1.2'}}}]
artifacts:
  - id: a
    sbom: input.json
    <<: &artifactDefaults
      enrichment:
        producer: {name: Publisher}
  - id: b
    sbom: second.json
    <<: *artifactDefaults
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, artifact := range m.Artifacts {
		if len(artifact.Enrichment.Fields) != 2 || string(artifact.Enrichment.Fields[0].Value) != `"Publisher"` || string(artifact.Enrichment.Fields[1].Value) != `"1.2"` {
			t.Fatalf("fields = %+v", artifact.Enrichment.Fields)
		}
	}
}

func TestEnrichmentLinksLoadAndMergePerLabel(t *testing.T) {
	m, err := manifest.Load(write(t, `version: 1
enrichment:
  subject:
    issueTracker: https://example.com/issues
    links:
      - label: Fact sheet
        url: https://ea.example/factsheet/shared
      - {label: Wiki, url: https://wiki.example/app, type: documentation-ish}
artifacts:
  - id: a
    sbom: a.json
    enrichment:
      subject:
        links:
          - {label: Fact sheet, url: https://ea.example/factsheet/a}
      replace: ["subject.links[Fact sheet]"]
`))
	if err == nil || !strings.Contains(err.Error(), `enrichment.subject.links[Wiki]: type "documentation-ish" is not a CycloneDX 1.6 external reference type`) {
		t.Fatalf("unknown type: %v", err)
	}
	m, err = manifest.Load(write(t, `version: 1
enrichment:
  subject:
    issueTracker: https://example.com/issues
    links:
      - label: Fact sheet
        url: https://ea.example/factsheet/shared
      - {label: Threat model, url: https://security.example/tm, type: threat-model}
artifacts:
  - id: a
    sbom: a.json
    enrichment:
      subject:
        links:
          - {label: Fact sheet, url: https://ea.example/factsheet/a}
      replace: ["subject.links[Fact sheet]"]
`))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range m.Artifacts[0].Enrichment.Fields {
		got[f.Field] = fmt.Sprintf("%s %s %t", f.Value, f.Source, f.Replace)
	}
	want := map[string]string{
		"subject.issueTracker":        `"https://example.com/issues" enrichment.subject.issueTracker false`,
		"subject.links[Fact sheet]":   `{"url":"https://ea.example/factsheet/a","type":"other"} artifacts[0].enrichment.subject.links[Fact sheet] true`,
		"subject.links[Threat model]": `{"url":"https://security.example/tm","type":"threat-model"} enrichment.subject.links[Threat model] false`,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}
}

func TestEnrichmentLinksRejectInvalidConfiguration(t *testing.T) {
	for _, tt := range []struct{ name, block, want string }{
		{"unknown key", "subject: {links: [{label: A, url: 'https://a.example', note: x}]}", "unknown key"},
		{"not a list", "subject: {links: text}", "enrichment.subject.links"},
		{"not a mapping", "subject: {links: [text]}", "enrichment.subject.links[0]"},
		{"label number", "subject: {links: [{label: 7, url: 'https://a.example'}]}", "must be a string"},
		{"missing label", "subject: {links: [{url: 'https://a.example'}]}", "enrichment.subject.links[0].label: is required"},
		{"duplicate label", "subject: {links: [{label: A, url: 'https://a.example'}, {label: A, url: 'https://b.example'}]}", "is listed more than once"},
		{"modeled type", "subject: {links: [{label: A, url: 'https://a.example', type: issue-tracker}]}", "modeled by enrichment.subject.issueTracker"},
		{"invalid url", "subject: {links: [{label: A, url: 'mailto:a@example.com'}]}", "enrichment.subject.links[0].url"},
		{"typed leaf url", "subject: {advisories: 'not a url'}", "enrichment.subject.advisories"},
		{"replace absent label", "subject: {links: [{label: A, url: 'https://a.example'}]}\n  replace: ['subject.links[B]']", "has no effective enrichment value"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := manifest.Load(write(t, "version: 1\nenrichment:\n  "+tt.block+"\nartifacts:\n  - id: a\n    sbom: a.json\n"))
			if err == nil || !strings.Contains(err.Error(), tt.want) || strings.Contains(err.Error(), "enrichment.Link") {
				t.Fatalf("error = %v; want %q", err, tt.want)
			}
		})
	}
}
