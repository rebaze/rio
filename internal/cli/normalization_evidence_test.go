package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizationLedgerAndConfidence(t *testing.T) {
	dir := project(t, tychoManifest, "tycho-rcp.cdx.json")
	requireExit(t, rio(t, dir, "normalize"), ExitOK)
	a := indexArtifact(t, dir, "target/rio", 0)
	ledger, ok := a["normalization"].(map[string]any)
	if !ok {
		t.Fatal("normalization ledger missing")
	}
	changes, _ := ledger["changes"].([]any)
	foundSpec, foundRepair, foundQualifier := false, false, false
	for _, raw := range changes {
		c := raw.(map[string]any)
		target, _ := c["target"].(string)
		if target == "/specVersion" && c["before"] == "1.4" && c["after"] == "1.6" {
			foundSpec = true
		}
		if target == "/components/7/purl" {
			foundRepair = true
			p, _ := c["resolution"].(map[string]any)
			if p["kind"] != "built-in-entry" || p["selector"] != "/entries/org.eclipse.osgi" {
				t.Fatalf("wrong provenance: %v", c)
			}
		}
		if strings.HasPrefix(target, "/components/2/properties/") {
			foundQualifier = true
		}
	}
	if !foundSpec || !foundRepair || !foundQualifier {
		t.Fatalf("incomplete ledger: %v", ledger)
	}
	if b, _ := ledger["bookkeeping"].([]any); len(b) == 0 {
		t.Fatal("missing separate bookkeeping")
	}
	if u, _ := ledger["unmapped"].([]any); len(u) != 1 {
		t.Fatalf("unmapped details: %v", ledger)
	}
	skipped, _ := ledger["skipped"].([]any)
	total := 0
	for _, raw := range skipped {
		n := raw.(map[string]any)["count"].(json.Number)
		i, _ := n.Int64()
		total += int(i)
	}
	if total != 4 {
		t.Fatalf("skipped denominator = %d", total)
	}
	out := decode(t, readFile(t, latestOutput(t, dir, "target/rio"), "rcp-client.cdx.json"))
	for _, raw := range out["components"].([]any) {
		comp := raw.(map[string]any)
		e, _ := comp["evidence"].(map[string]any)
		ids, _ := e["identity"].([]any)
		for _, raw := range ids {
			id := raw.(map[string]any)
			if _, ok := id["confidence"]; ok {
				t.Fatalf("invented confidence: %v", id)
			}
			if _, ok := id["methods"]; ok {
				t.Fatalf("confidence-requiring methods emitted: %v", id)
			}
		}
	}
}

func TestNormalizationLedgerNoOpAndLegacySubject(t *testing.T) {
	for _, override := range []bool{false, true} {
		t.Run(fmt.Sprint(override), func(t *testing.T) {
			man := "version: 1\nartifacts:\n  - id: app\n    sbom: in/plain-maven.cdx.json\n"
			if override {
				man += "    subject:\n      name: replacement\n      version: 9.0.0\n"
			}
			dir := project(t, man, "plain-maven.cdx.json")
			requireExit(t, rio(t, dir, "normalize"), ExitOK)
			a := indexArtifact(t, dir, "target/rio", 0)
			l, _ := a["normalization"].(map[string]any)
			if l == nil {
				t.Fatal("no ledger")
			}
			changes, _ := l["changes"].([]any)
			if !override && len(changes) != 0 {
				t.Fatalf("no-op claims changes: %v", changes)
			}
			if override {
				found := false
				for _, raw := range changes {
					c := raw.(map[string]any)
					if c["target"] == "/metadata/component/name" && c["after"] == "replacement" {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing subject override: %v", changes)
				}
			}
		})
	}
}

// The same-looking dependencies still need distinct pointers; identity evidence
// omission is checked against the embedded schema by normalize itself.
func TestLedgerDuplicateComponentsAndOldIdentity(t *testing.T) {
	for _, spec := range []string{"1.5", "1.6"} {
		t.Run(spec, func(t *testing.T) {
			man := `version: 1
artifacts:
  - id: app
    sbom: input.json
    transforms:
      - repair-purl:
          ecosystem: p2
output:
  specVersionFloor: "` + spec + `"
`
			dir := project(t, man)
			comp := `{"type":"library","name":"com.google.gson","version":"2.8.9.today","group":"p2.eclipse.plugin","purl":"pkg:p2/com.google.gson@2.8.9.today?classifier=osgi.bundle"}`
			input := `{"bomFormat":"CycloneDX","specVersion":"` + spec + `","version":1,"metadata":{"component":{"type":"application","name":"app","version":"1"}},"components":[` + comp + `,` + strings.Replace(comp, `"type":"library"`, `"type":"library","bom-ref":"second"`, 1) + `]}`
			if err := os.WriteFile(filepath.Join(dir, "input.json"), []byte(input), 0600); err != nil {
				t.Fatal(err)
			}
			requireExit(t, rio(t, dir, "normalize"), ExitOK)
			ledger := indexArtifact(t, dir, "target/rio", 0)["normalization"].(map[string]any)
			seen := map[string]bool{}
			for _, raw := range ledger["changes"].([]any) {
				c := raw.(map[string]any)
				if strings.HasSuffix(c["target"].(string), "/purl") {
					seen[c["target"].(string)] = true
				}
			}
			if !seen["/components/0/purl"] || !seen["/components/1/purl"] {
				t.Fatalf("ambiguous repair targets: %v", seen)
			}
		})
	}
}

func TestLedgerEnrichmentAndContext(t *testing.T) {
	dir := enrichmentProject(t, `version: 1
enrichment:
  producer:
    name: Example Team
artifacts:
  - id: app
    sbom: input.json
`)
	requireExit(t, rio(t, dir, "normalize"), ExitOK)
	a := indexArtifact(t, dir, "target/rio", 0)
	l := a["normalization"].(map[string]any)
	found := false
	for _, raw := range l["changes"].([]any) {
		c := raw.(map[string]any)
		if c["rule"] == "enrichment" {
			found = true
			p := c["resolution"].(map[string]any)
			if p["kind"] != "manifest" {
				t.Fatalf("lost source: %v", c)
			}
		}
	}
	if !found {
		t.Fatal("no enrichment changes")
	}
	var one, two []byte
	dir, one, two = contextProject(t)
	writeContextFile(t, dir, one, two)
	requireExit(t, rio(t, dir, "normalize"), ExitOK)
	a = indexArtifact(t, dir, "target/rio", 0)
	l = a["normalization"].(map[string]any)
	found = false
	for _, list := range []string{"changes", "bookkeeping"} {
		for _, raw := range l[list].([]any) {
			c := raw.(map[string]any)
			if c["rule"] == "context" {
				found = true
				p := c["resolution"].(map[string]any)
				if p["kind"] != "context-file" || p["sha256"] == "" {
					t.Fatalf("lost context source: %v", c)
				}
			}
		}
	}
	if !found {
		t.Fatal("no context changes")
	}
}

func TestLedgerContextAssertionWithoutNativeFields(t *testing.T) {
	dir, one, two := contextProject(t)
	writeContextFile(t, dir, one, two)
	raw := decode(t, readFile(t, dir, "context.json"))
	for _, v := range raw["artifacts"].([]any) {
		a := v.(map[string]any)
		delete(a, "source")
		delete(a, "build")
		a["generator"] = map[string]any{"name": "synthetic-generator"}
	}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "context.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	requireExit(t, rio(t, dir, "normalize"), ExitOK)
	l := indexArtifact(t, dir, "target/rio", 0)["normalization"].(map[string]any)
	found := false
	for _, v := range l["changes"].([]any) {
		c := v.(map[string]any)
		if c["rule"] == "context" {
			p, _ := c["resolution"].(map[string]any)
			if p["kind"] == "context-file" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("context-only assertion not explained: %v", l)
	}
}
