package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/rebaze/rio/internal/index"
)

// profileRepairInput is synthetic: a product whose SBOM creator, subject
// creator, concluded licence, assembled libraries and the subject's own
// dependency completeness come from the generator. It lacks only what a
// shipped file needs (filename, SHA-512 and the three BSI properties) and the
// subject's level, which the build context file supplies.
const profileRepairInput = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-10-26T10:00:00Z",
    "manufacturer": {"name": "Example GmbH", "contact": [{"email": "sbom@example.org"}]},
    "properties": [{"name": "example:fixture", "value": "synthetic data for rio tests; not a real product"}],
    "component": {
      "type": "application", "bom-ref": "subject", "name": "cart-api", "version": "1.4.0",
      "manufacturer": {"name": "Example GmbH", "url": ["https://example.org"]},
      "licenses": [{"acknowledgement": "concluded", "expression": "Apache-2.0"}]
    }
  },
  "components": [%s, %s],
  "dependencies": [
    {"ref": "subject", "dependsOn": ["zlib", "openssl"]},
    {"ref": "zlib", "dependsOn": []},
    {"ref": "openssl", "dependsOn": []}
  ],
  "compositions": [{"aggregate": "complete", "dependencies": ["subject", "zlib", "openssl"]}]
}`

func assembledLibrary(name, version, licence string) string {
	return fmt.Sprintf(`{"type": "library", "bom-ref": %q, "name": %q, "version": %q,
      "manufacturer": {"name": "Example GmbH", "contact": [{"email": "sbom@example.org"}]},
      "licenses": [{"acknowledgement": "concluded", "expression": %q}],
      "properties": [
        {"name": "rio:tr-03183-2:level", "value": "assembled"},
        {"name": "bsi:component:executable", "value": "non-executable"},
        {"name": "bsi:component:archive", "value": "no archive"},
        {"name": "bsi:component:structured", "value": "unstructured"}
      ]}`, name, name, version, licence)
}

// profileRepairContext asserts two shipped files and the subject's level for
// the SBOM with the given bytes.
func profileRepairContext(sbom []byte) string {
	return fmt.Sprintf(`{"contextVersion": 1, "artifacts": [{"id": "cart-api", "sbom": {"sha256": %q}, "level": "logical",
  "distributions": [
    {"name": "cart-api-1.4.0-linux-amd64.tar.gz", "sha256": %q, "sha512": %q, "executable": false, "archive": true, "structured": true,
     "url": "https://downloads.example.org/cart-api/1.4.0/cart-api-1.4.0-linux-amd64.tar.gz"},
    {"name": "cart-api-1.4.0-windows-amd64.exe", "sha256": %q, "sha512": %q, "executable": true, "archive": false, "structured": false}
  ]}]}`, index.SHA256Bytes(sbom), strings.Repeat("1", 64), strings.Repeat("2", 128), strings.Repeat("3", 64), strings.Repeat("4", 128))
}

func TestRootProfileRepairedByContext(t *testing.T) {
	input := []byte(fmt.Sprintf(profileRepairInput, assembledLibrary("zlib", "1.3.1", "Zlib"), assembledLibrary("openssl", "3.0.13", "Apache-2.0")))
	dir := t.TempDir()
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest := func(sbom string, withContext bool) []byte {
		m := "version: 1\ngate:\n  profile: " + profileName + "\nartifacts:\n  - id: cart-api\n    sbom: " + sbom + "\n"
		if withContext {
			m += "    context: {file: context.json, require: [level]}\n"
		}
		return []byte(m)
	}
	write("in.cdx.json", input)
	t.Chdir(dir)

	// Without the context the subject is checked as one fully described file.
	write("rio.yaml", manifest("in.cdx.json", false))
	code, _, _, stderr := runRoot(t)
	if code != ExitGate || !strings.Contains(stderr, "subject.deployableHash") || !strings.Contains(stderr, "subject.filename") {
		t.Fatalf("without context: exit %d\n%s", code, stderr)
	}

	write("rio.yaml", manifest("in.cdx.json", true))
	write("context.json", []byte(profileRepairContext(input)))
	code, d, runDir, stderr := runRoot(t)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	c := d.Artifacts[0].Checks
	if c == nil || c.Gate != "pass" || c.Profile == nil || c.Profile.Name != profileName || c.Profile.GuidelineVersion != "2.1.0" {
		t.Fatalf("checks = %+v", c)
	}
	wantLevels := map[string]int{"full": 2, "logical": 1, "assembled": 2, "identified": 0, "referenced": 0}
	if diff := cmp.Diff(wantLevels, c.ProfileLevels); diff != "" {
		t.Errorf("profileLevels (-want +got):\n%s", diff)
	}
	if n := len(d.Artifacts[0].Distributions); n != 2 {
		t.Errorf("receipt distributions = %d, want 2", n)
	}
	output := readFile(t, runDir, "cart-api.cdx.json")
	out := decode(t, output)
	// The dependency component array is unchanged; the shipped files nest
	// under the subject.
	if !jsonEqual(t, out["components"], decode(t, input)["components"]) {
		t.Fatalf("output components changed: %s", mustMarshal(t, out["components"]))
	}
	files, _ := out["metadata"].(map[string]any)["component"].(map[string]any)["components"].([]any)
	if len(files) != 2 || files[0].(map[string]any)["bom-ref"] != "rio:distribution:cart-api-1.4.0-linux-amd64.tar.gz" {
		t.Fatalf("subject components: %s", mustMarshal(t, files))
	}
	var idx struct {
		Artifacts []struct {
			IntegrityFindings []any `json:"integrityFindings"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(readFile(t, runDir, "index.json"), &idx); err != nil {
		t.Fatal(err)
	}
	if n := len(idx.Artifacts[0].IntegrityFindings); n != 0 {
		t.Fatalf("index.json integrity findings: %v", idx.Artifacts[0].IntegrityFindings)
	}

	// Re-normalizing rio's own output with the same assertions adds nothing.
	write("again.cdx.json", output)
	write("rio.yaml", manifest("again.cdx.json", true))
	write("context.json", []byte(profileRepairContext(output)))
	code, again, againDir, stderr := runRoot(t)
	if code != 0 {
		t.Fatalf("re-normalize: exit %d\n%s", code, stderr)
	}
	second := decode(t, readFile(t, againDir, "cart-api.cdx.json"))
	for _, key := range []string{"components", "dependencies", "compositions"} {
		if !jsonEqual(t, out[key], second[key]) {
			t.Errorf("%s changed on re-normalize:\n%s\n%s", key, mustMarshal(t, out[key]), mustMarshal(t, second[key]))
		}
	}
	for _, key := range []string{"properties", "components", "externalReferences"} {
		subjectField := func(doc map[string]any) any {
			return doc["metadata"].(map[string]any)["component"].(map[string]any)[key]
		}
		if !jsonEqual(t, subjectField(out), subjectField(second)) {
			t.Errorf("subject %s changed on re-normalize: %s", key, mustMarshal(t, subjectField(second)))
		}
	}
	ac := again.Artifacts[0].Checks
	if ac.Gate != c.Gate || !cmp.Equal(ac.ProfileLevels, c.ProfileLevels) || !cmp.Equal(ac.Profile, c.Profile) || ac.ComponentsEvaluated != c.ComponentsEvaluated ||
		!cmp.Equal(again.Artifacts[0].Distributions, d.Artifacts[0].Distributions) {
		t.Errorf("receipt differs in substance:\nfirst  %+v\nsecond %+v", c, ac)
	}
}

func jsonEqual(t *testing.T, a, b any) bool {
	t.Helper()
	return mustMarshal(t, a) == mustMarshal(t, b)
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
