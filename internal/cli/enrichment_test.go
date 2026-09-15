package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

const enrichmentInput = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"timestamp":"2025-01-01T00:00:00Z","tools":[{"name":"Fixture generator","version":"1.0"}],"component":{"type":"application","name":"widget","version":"1.0","purl":"pkg:generic/widget@1.0","bom-ref":"root"}},"components":[{"type":"library","name":"dependency","version":"2.0","purl":"pkg:generic/dependency@2.0","bom-ref":"dependency"}],"dependencies":[{"ref":"root","dependsOn":["dependency"]},{"ref":"dependency","dependsOn":[]}]}`

func enrichmentProject(t *testing.T, config string) string {
	t.Helper()
	dir := project(t, config)
	if err := os.WriteFile(filepath.Join(dir, "input.json"), []byte(enrichmentInput), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A missing enrichment phase must fail this test even if the existing gate passes.
func TestNormalizeEnrichmentRecordsAndPreserves(t *testing.T) {
	dir := enrichmentProject(t, `version: 1
enrichment:
  producer:
    name: Example SBOM Team
  dataLicense: CC0-1.0
  subject:
    supplier:
      name: Example Distributor
    securityContact: mailto:security@example.com
artifacts:
  - id: widget
    sbom: input.json
`)
	r := rio(t, dir, "normalize", "--attest")
	if r.exit != 0 {
		t.Fatalf("normalize: exit %d: %s", r.exit, r.stderr)
	}
	output := readFile(t, dir, "target/rio/widget.cdx.json")
	out := decode(t, output)
	in := decode(t, []byte(enrichmentInput))
	if diff := cmp.Diff(in["components"], out["components"]); diff != "" {
		t.Fatal(diff)
	}
	if diff := cmp.Diff(in["dependencies"], out["dependencies"]); diff != "" {
		t.Fatal(diff)
	}
	meta := out["metadata"].(map[string]any)
	if meta["timestamp"] != "2025-01-01T00:00:00Z" {
		t.Fatal("changed original timestamp")
	}
	if got := meta["manufacturer"].(map[string]any)["name"]; got != "Example SBOM Team" {
		t.Fatal(got)
	}
	sub := meta["component"].(map[string]any)
	if sub["bom-ref"] != "root" || sub["supplier"].(map[string]any)["name"] != "Example Distributor" {
		t.Fatal(sub)
	}
	refs := sub["externalReferences"].([]any)
	if len(refs) != 1 || refs[0].(map[string]any)["type"] != "security-contact" || refs[0].(map[string]any)["url"] != "mailto:security@example.com" {
		t.Fatal(refs)
	}
	idx := indexOf(t, r, "target/rio")
	art := idx["artifacts"].([]any)[0].(map[string]any)
	records := art["enrichment"].(map[string]any)
	if records["version"] != json.Number("1") {
		t.Fatal(records)
	}
	changes := records["changes"].([]any)
	if len(changes) != 4 {
		t.Fatalf("want four recorded additions: %v", changes)
	}
	first := changes[0].(map[string]any)
	if first["before"] != nil || first["field"] != "dataLicense" || first["assertion"] != "producer" {
		t.Fatal(first)
	}
	source := first["source"].(map[string]any)
	if source["path"] != "rio.yaml" || source["selector"] != "enrichment.dataLicense" || source["sha256"] != idx["manifest"].(map[string]any)["sha256"] {
		t.Fatal(source)
	}
	props := properties(t, out)["rebaze:normalize:enrichment"]
	if len(props) != 4 {
		t.Fatalf("want embedded change records, got %v", props)
	}
	for _, value := range props {
		property := decode(t, []byte(value))
		if property["version"] != json.Number("1") {
			t.Fatalf("standalone SBOM enrichment property is not versioned: %v", property)
		}
	}
	statement := decode(t, readFile(t, dir, "target/rio/widget.intoto.json"))
	if diff := cmp.Diff(art, statement["predicate"].(map[string]any)["artifact"]); diff != "" {
		t.Fatal(diff)
	}
	r = rio(t, dir, "normalize", "--attest", "--out", "again")
	if r.exit != 0 || !bytes.Equal(output, readFile(t, dir, "again/widget.cdx.json")) {
		t.Fatalf("nondeterministic output: %s", r.stderr)
	}
	// Reprocessing enriched input must not grow the enrichment audit trail.
	if err := os.WriteFile(filepath.Join(dir, "input.json"), output, 0644); err != nil {
		t.Fatal(err)
	}
	r = rio(t, dir, "normalize", "--out", "reapplied")
	if r.exit != 0 {
		t.Fatal(r.stderr)
	}
	reapplied := decode(t, readFile(t, dir, "reapplied/widget.cdx.json"))
	if n := len(properties(t, reapplied)["rebaze:normalize:enrichment"]); n != 4 {
		t.Fatalf("duplicate enrichment records: %d", n)
	}
}

func TestNormalizeEnrichmentRefusesBeforeWriting(t *testing.T) {
	for _, tc := range []struct{ name, config, want string }{
		{"conflict", "subject:\n    name: different", "subject.name"},
		{"identity mismatch", "replace: [subject.version]\n  subject:\n    version: '2.0'", "purl"},
		{"invalid data license", "dataLicense: Not-A-License", "dataLicense"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := enrichmentProject(t, "version: 1\nenrichment:\n  "+tc.config+"\nartifacts:\n  - id: widget\n    sbom: input.json\n")
			r := rio(t, dir, "normalize", "--attest")
			if r.exit != 2 || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("exit=%d stderr=%s", r.exit, r.stderr)
			}
			if _, err := os.Stat(filepath.Join(dir, "target/rio")); !os.IsNotExist(err) {
				t.Fatalf("wrote output for invalid enrichment: %v", err)
			}
		})
	}
}

func TestNormalizeEnrichmentIdentityOverridePreservesReferences(t *testing.T) {
	dir := enrichmentProject(t, `version: 1
artifacts:
  - id: widget
    sbom: input.json
    enrichment:
      replace: [subject.name, subject.version, subject.purl]
      subject:
        name: product
        version: '2.0'
        purl: pkg:generic/product@2.0
`)
	r := rio(t, dir, "normalize")
	if r.exit != 0 {
		t.Fatal(r.stderr)
	}
	out := decode(t, readFile(t, dir, "target/rio/widget.cdx.json"))
	sub := out["metadata"].(map[string]any)["component"].(map[string]any)
	if sub["name"] != "product" || sub["version"] != "2.0" || sub["purl"] != "pkg:generic/product@2.0" || sub["bom-ref"] != "root" {
		t.Fatal(sub)
	}
	if diff := cmp.Diff(decode(t, []byte(enrichmentInput))["dependencies"], out["dependencies"]); diff != "" {
		t.Fatal(diff)
	}
}

// The public showcase data is an executable product fixture, not a screenshot
// or a test-only construction. This catches stale examples and scope regressions.
func TestEnrichmentDemoFixtures(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(filepath.Join("..", "..", "tools", "demo-enrichment"))); err != nil {
		t.Fatal(err)
	}
	r := rio(t, dir, "normalize", "--manifest", "rio.yaml", "--out", "enriched", "--attest", "--gate", "fail")
	if r.exit != 0 {
		t.Fatal(r.stderr)
	}
	for _, id := range []string{"console", "agent"} {
		in := decode(t, readFile(t, dir, "inputs", id+".cdx.json"))
		out := decode(t, readFile(t, dir, "enriched", id+".cdx.json"))
		for _, key := range []string{"components", "dependencies"} {
			if diff := cmp.Diff(in[key], out[key]); diff != "" {
				t.Fatalf("%s changed %s: %s", id, key, diff)
			}
		}
		meta := out["metadata"].(map[string]any)
		inputMeta := in["metadata"].(map[string]any)
		sub := meta["component"].(map[string]any)
		if meta["timestamp"] != inputMeta["timestamp"] || sub["bom-ref"] != inputMeta["component"].(map[string]any)["bom-ref"] {
			t.Fatal("demo changed source timestamp or local identity")
		}
		if sub["name"] != id || sub["version"] != "1.0.0" || sub["group"] != "com.example" {
			t.Fatal(sub)
		}
		if sub["manufacturer"].(map[string]any)["name"] != "Example Products" || sub["supplier"].(map[string]any)["name"] != "Example Distribution" || meta["manufacturer"].(map[string]any)["name"] != "Example Build Services" {
			t.Fatal("organization roles mixed up")
		}
		generator := meta["tools"].(map[string]any)["components"].([]any)[0]
		if diff := cmp.Diff(inputMeta["tools"].(map[string]any)["components"].([]any)[0], generator); diff != "" {
			t.Fatal(diff)
		}
		refs := sub["externalReferences"].([]any)
		found := false
		for _, v := range refs {
			ref := v.(map[string]any)
			if ref["type"] == "documentation" && ref["url"] == "https://products.example.com/"+id+"/docs" {
				found = true
			}
		}
		if !found {
			t.Fatalf("artifact-specific documentation lost: %v", refs)
		}
	}
	r = rio(t, dir, "normalize", "--manifest", "conflict.yaml", "--out", "refused")
	if r.exit != 2 {
		t.Fatalf("demo conflict exit=%d", r.exit)
	}
	if _, err := os.Stat(filepath.Join(dir, "refused")); !os.IsNotExist(err) {
		t.Fatalf("conflict wrote files: %v", err)
	}
	r = rio(t, dir, "normalize", "--manifest", "replace.yaml", "--out", "replaced", "--attest")
	if r.exit != 0 {
		t.Fatal(r.stderr)
	}
	art := indexOf(t, r, "replaced")["artifacts"].([]any)[0].(map[string]any)
	changes := art["enrichment"].(map[string]any)["changes"].([]any)
	if len(changes) != 3 {
		t.Fatalf("demo replacement changed more than the three authorized identity fields: %v", changes)
	}
	for _, v := range changes {
		c := v.(map[string]any)
		switch c["field"] {
		case "subject.name", "subject.version", "subject.purl":
		default:
			t.Fatal(c)
		}
	}
}
