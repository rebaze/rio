package cli

import (
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"os"
	"path/filepath"
	"testing"
)

func TestEffectiveChecksNestedEmptyAndMode(t *testing.T) {
	for _, mode := range []string{"warn", "fail"} {
		for _, empty := range []bool{false, true} {
			name := mode
			if empty {
				name += "-empty"
			}
			t.Run(name, func(t *testing.T) {
				man := "version: 1\nartifacts:\n  - id: app\n    sbom: input.json\n"
				if empty {
					man += "gate:\n  require: []\n"
				}
				dir := project(t, man)
				raw := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"app","version":"1"}},"components":[{"type":"library","name":"outer","version":"1","purl":"pkg:generic/outer@1","components":[{"type":"library","name":"nested"}]}]}`
				if err := os.WriteFile(filepath.Join(dir, "input.json"), []byte(raw), 0600); err != nil {
					t.Fatal(err)
				}
				want := ExitOK
				if mode == "fail" && !empty {
					want = ExitGate
				}
				requireExit(t, rio(t, dir, "normalize", "--gate", mode), want)
				a := indexArtifact(t, dir, "target/rio", 0)
				c, _ := a["checks"].(map[string]any)
				if c == nil {
					t.Fatal("effective checks missing")
				}
				if c["mode"] != mode || c["componentScope"] != "all components including nested" || c["componentCount"] != json.Number("2") {
					t.Fatalf("wrong mode/scope/count: %v", c)
				}
				evals, _ := c["evaluations"].([]any)
				wantLen := 5
				if empty {
					wantLen = 2
				}
				if len(evals) != wantLen {
					t.Fatalf("evaluations = %v", evals)
				}
				for _, v := range evals {
					e := v.(map[string]any)
					if e["scope"] == "subject" {
						if e["evaluated"] != json.Number("1") || e["failed"] != json.Number("0") {
							t.Fatalf("unconditional subject check: %v", e)
						}
					}
					if e["scope"] == "components" && e["requirement"] == "version" {
						if e["evaluated"] != json.Number("2") || e["failed"] != json.Number("1") {
							t.Fatalf("nested not evaluated: %v", e)
						}
					}
				}
				expected := "evaluated"
				if empty {
					expected = "not-evaluated"
				}
				if c["componentEvaluation"] != expected {
					t.Fatalf("empty requirements claim a pass: %v", c)
				}
			})
		}
	}
}

func TestNormalizationScopeExcludesDeliveryConfiguration(t *testing.T) {
	dir := project(t, tychoManifest, "tycho-rcp.cdx.json")
	requireExit(t, rio(t, dir, "normalize"), ExitOK)
	idx := decode(t, readFile(t, dir, "target/rio/index.json"))
	s, _ := idx["normalizationScope"].(map[string]any)
	if s == nil {
		t.Fatal("scope missing")
	}
	if s["specVersionFloor"] != "1.6" || s["manifestSHA256"] != idx["manifest"].(map[string]any)["sha256"] {
		t.Fatalf("scope binding/floor: %v", s)
	}
	explicit, _ := s["explicitArtifacts"].([]any)
	if len(explicit) != 1 || explicit[0] != "rcp-client" {
		t.Fatalf("explicit scope: %v", s)
	}
	arts, _ := s["artifacts"].([]any)
	if len(arts) != 1 {
		t.Fatalf("membership: %v", s)
	}
	tr := arts[0].(map[string]any)["transforms"].([]any)[0].(map[string]any)
	options := tr["options"].(map[string]any)
	if options["groupPrefix"] != "p2." || options["classifier"] != "osgi.bundle" {
		t.Fatalf("effective options: %v", tr)
	}
}

func TestScopeTwoSetsExclusionsAndInheritedEnrichment(t *testing.T) {
	dir := t.TempDir()
	setWrite(t, dir, "rio.yaml", `version: 1
enrichment:
  producer:
    name: Synthetic Team
artifactSets:
  - modules: services/*/pom.xml
    exclude: [services/excluded/pom.xml]
    idFrom: module-directory
    sbom: target/*.json
  - modules: clients/*/pom.xml
    idFrom: module-directory
    sbom: target/*.json
`)
	setModule(t, dir, "services/server")
	setModule(t, dir, "clients/client")
	setWrite(t, dir, "services/excluded/pom.xml", "<project/>") // excluded before resolving missing SBOM
	requireExit(t, rio(t, dir, "normalize"), ExitOK)
	idx := decode(t, readFile(t, dir, "target/rio/index.json"))
	scope := idx["normalizationScope"].(map[string]any)
	sets := scope["artifactSets"].([]any)
	if len(sets) != 2 || len(scope["explicitArtifacts"].([]any)) != 0 {
		t.Fatalf("set selection: %v", scope)
	}
	if sets[0].(map[string]any)["exclude"].([]any)[0] != "services/excluded/pom.xml" || sets[0].(map[string]any)["artifactIDs"].([]any)[0] != "server" || sets[1].(map[string]any)["artifactIDs"].([]any)[0] != "client" {
		t.Fatalf("membership/exclusions: %v", sets)
	}
	for _, v := range idx["artifacts"].([]any) {
		a := v.(map[string]any)
		if a["enrichment"] == nil {
			t.Fatal("inherited enrichment missing")
		}
	}
}

func TestFutureSchemaCheckRemainsUnavailable(t *testing.T) {
	dir := project(t, "version: 1\nartifacts:\n  - id: future\n    sbom: in/future-1.9.cdx.json\n", "future-1.9.cdx.json")
	requireExit(t, rio(t, dir, "normalize"), ExitOK)
	c := indexArtifact(t, dir, "target/rio", 0)["checks"].(map[string]any)
	if c["schemaValidation"] != "not-available" {
		t.Fatalf("future schema claimed validated: %v", c)
	}
}

func TestKnownExtensionsRefuseContradictionsAndKeepFutureOpaque(t *testing.T) {
	dir := project(t, tychoManifest, "tycho-rcp.cdx.json")
	requireExit(t, rio(t, dir, "normalize"), ExitOK)
	original := readFile(t, dir, "target/rio/index.json")
	for _, kind := range []string{"scope", "checks", "future"} {
		t.Run(kind, func(t *testing.T) {
			idx := decode(t, original)
			a := idx["artifacts"].([]any)[0].(map[string]any)
			switch kind {
			case "scope":
				idx["normalizationScope"].(map[string]any)["manifestSHA256"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			case "checks":
				a["checks"].(map[string]any)["evaluations"].([]any)[0].(map[string]any)["evaluated"] = 77
			case "future":
				a["checks"] = map[string]any{"version": 2, "future": true}
				idx["normalizationScope"] = map[string]any{"version": 2, "future": true}
			}
			raw, err := json.Marshal(idx)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := delivery.ParseIndex(raw)
			if kind != "future" {
				if err == nil {
					t.Fatal("contradictory known extension accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			out, err := json.Marshal(parsed)
			if err != nil {
				t.Fatal(err)
			}
			round := decode(t, out)
			if round["normalizationScope"].(map[string]any)["future"] != true {
				t.Fatal("future source lost")
			}
		})
	}
	// An old index without extensions remains readable.
	old := decode(t, original)
	delete(old, "normalizationScope")
	for _, v := range old["artifacts"].([]any) {
		a := v.(map[string]any)
		delete(a, "checks")
		delete(a, "normalization")
	}
	raw, _ := json.Marshal(old)
	if _, err := delivery.ParseIndex(raw); err != nil {
		t.Fatal(err)
	}
}
