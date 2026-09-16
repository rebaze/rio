package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/index"
)

func contextProject(t *testing.T) (string, []byte, []byte) {
	t.Helper()
	one := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"timestamp":"2025-01-01T00:00:00Z","component":{"type":"application","name":"one"},"tools":{"services":[{"name":"original"}]}},"components":[{"type":"library","name":"dependency"}]}`)
	two := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"two"}}}`)
	dir := t.TempDir()
	manifest := `version: 1
artifacts:
  - id: one
    sbom: one.json
    context: {file: context.json}
  - id: two
    sbom: two.json
    context: {file: context.json}
output:
  specVersionFloor: "1.6"
`
	for name, data := range map[string][]byte{"rio.yaml": []byte(manifest), "one.json": one, "two.json": two} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, one, two
}

func writeContextFile(t *testing.T, dir string, one, two []byte) {
	t.Helper()
	body := fmt.Sprintf(`{"contextVersion":1,"artifacts":[{"id":"one","sbom":{"sha256":"%s"},"source":{"repository":"https://code.example/one","revision":"%s"},"generator":{"name":"generator"}},{"id":"two","sbom":{"sha256":"%s"},"source":{"repository":"https://code.example/two"},"build":{"url":"https://ci.example/run/2","id":"2"}}]}`, index.SHA256Bytes(one), "1111111111111111111111111111111111111111", index.SHA256Bytes(two))
	if err := os.WriteFile(filepath.Join(dir, "context.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeContextSharedSnapshotAndStatement(t *testing.T) {
	dir, one, two := contextProject(t)
	requireExit(t, rio(t, dir, "plan", "--json"), ExitOK)
	requireExit(t, rio(t, dir, "normalize"), ExitUsage)
	if _, err := os.Stat(filepath.Join(dir, "target")); !os.IsNotExist(err) {
		t.Fatalf("failed normalize wrote outputs: %v", err)
	}
	writeContextFile(t, dir, one, two)
	requireExit(t, rio(t, dir, "normalize", "--attest"), ExitOK)
	idx := decode(t, readFile(t, dir, "target", "rio", "index.json"))
	rows := idx["artifacts"].([]any)
	if len(rows) != 2 {
		t.Fatal(rows)
	}
	for i, id := range []string{"one", "two"} {
		row := rows[i].(map[string]any)
		ctx := row["context"].(map[string]any)
		if ctx["selector"] != fmt.Sprintf("/artifacts/%d", i) || ctx["assertion"] != "producer" {
			t.Fatalf("context: %v", ctx)
		}
		effective := ctx["effective"].(map[string]any)
		if effective["id"] != id || effective["source"].(map[string]any)["workspace"] != "unknown" {
			t.Fatalf("effective: %v", effective)
		}
		out := decode(t, readFile(t, dir, "target", "rio", id+".cdx.json"))
		if id == "one" {
			meta := out["metadata"].(map[string]any)
			if meta["timestamp"] != "2025-01-01T00:00:00Z" || out["components"].([]any)[0].(map[string]any)["name"] != "dependency" {
				t.Fatal("context changed original timestamp or dependency")
			}
			tools := meta["tools"].(map[string]any)
			if tools["services"].([]any)[0].(map[string]any)["name"] != "original" || len(tools["components"].([]any)) != 1 {
				t.Fatalf("generator/tool roles changed: %v", tools)
			}
		}
		var stored map[string]any
		for _, raw := range out["metadata"].(map[string]any)["properties"].([]any) {
			p := raw.(map[string]any)
			if p["name"] == "rebaze:normalize:context" {
				if err := json.Unmarshal([]byte(p["value"].(string)), &stored); err != nil {
					t.Fatal(err)
				}
			}
		}
		if stored == nil || stored["file"].(map[string]any)["sha256"] != ctx["file"].(map[string]any)["sha256"] {
			t.Fatal("SBOM context differs from index")
		}
		x, _ := json.Marshal(ctx)
		storedJSON, _ := json.Marshal(stored)
		if !bytes.Equal(x, storedJSON) {
			t.Fatalf("SBOM property differs from index context:\n%s\n%s", storedJSON, x)
		}
		stmt := decode(t, readFile(t, dir, "target", "rio", id+".intoto.json"))
		predicate := stmt["predicate"].(map[string]any)
		artifact := predicate["artifact"].(map[string]any)
		y, _ := json.Marshal(artifact["context"])
		if !bytes.Equal(x, y) {
			t.Fatal("statement context differs")
		}
	}
	first := readFile(t, dir, "target", "rio", "index.json")
	requireExit(t, rio(t, dir, "normalize", "--attest"), ExitOK)
	if !bytes.Equal(first, readFile(t, dir, "target", "rio", "index.json")) {
		t.Fatal("same inputs changed index")
	}
}

func TestNormalizeMalformedPriorContextWritesNothing(t *testing.T) {
	dir, _, two := contextProject(t)
	record := fmt.Sprintf(`{"version":1,"file":{"path":"old.json","sha256":"%s"},"selector":"/artifacts/0","effective":{"id":"one","sbom":{"sha256":"%s"}},"defaulted":[],"changes":[null],"assertion":"producer"}`, strings.Repeat("b", 64), strings.Repeat("a", 64))
	property, _ := json.Marshal(record)
	one := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"one"},"properties":[{"name":"rebaze:normalize:context","value":` + string(property) + `}]}}`)
	if err := os.WriteFile(filepath.Join(dir, "one.json"), one, 0o644); err != nil {
		t.Fatal(err)
	}
	writeContextFile(t, dir, one, two)
	r := rio(t, dir, "normalize")
	requireExit(t, r, ExitUsage)
	requireStderr(t, r, "one", "context")
	if _, err := os.Stat(filepath.Join(dir, "target")); !os.IsNotExist(err) {
		t.Fatalf("malformed prior context wrote outputs: %v", err)
	}
}

func TestNormalizeContextLaterDigestFailureWritesNothing(t *testing.T) {
	dir, one, two := contextProject(t)
	writeContextFile(t, dir, one, two)
	if err := os.WriteFile(filepath.Join(dir, "two.json"), append(two, ' '), 0o644); err != nil {
		t.Fatal(err)
	}
	r := rio(t, dir, "normalize")
	requireExit(t, r, ExitUsage)
	requireStderr(t, r, "two", "sha256")
	if _, err := os.Stat(filepath.Join(dir, "target")); !os.IsNotExist(err) {
		t.Fatalf("failed normalize wrote outputs: %v", err)
	}
}
