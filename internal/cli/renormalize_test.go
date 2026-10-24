package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/rebaze/rio/internal/index"
)

// rioEntries counts rio's own entries in metadata.tools, in either shape.
func rioEntries(t *testing.T, doc map[string]any) int {
	t.Helper()
	var list []any
	switch tools := doc["metadata"].(map[string]any)["tools"].(type) {
	case []any:
		list = tools
	case map[string]any:
		list, _ = tools["components"].([]any)
	}
	n := 0
	for _, raw := range list {
		if e, ok := raw.(map[string]any); ok && e["name"] == "rio" && e["version"] == version {
			n++
		}
	}
	return n
}

func normalizeOnce(t *testing.T, dir, manifest, out string) []byte {
	t.Helper()
	r := rio(t, dir, "normalize", "--manifest", manifest, "--out", out, "--quiet")
	requireExit(t, r, ExitOK)
	return readFile(t, latestOutput(t, dir, out), "a.cdx.json")
}

// Normalizing rio's own output with the same build must succeed and leave one
// rio entry in metadata.tools (#181).
func TestNormalizeOwnOutputRecordsRioOnce(t *testing.T) {
	inputs := map[string]string{
		"object form":       `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"a"}},"components":[{"type":"library","name":"dep","version":"1"}]}`,
		"legacy array form": `{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"metadata":{"component":{"type":"application","name":"a"},"tools":[{"vendor":"x","name":"gen","version":"1"}]},"components":[{"type":"library","name":"dep","version":"1"}]}`,
	}
	for name, in := range inputs {
		for _, withContext := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s context=%v", name, withContext), func(t *testing.T) {
				dir := t.TempDir()
				write := func(file, body string) {
					if err := os.WriteFile(filepath.Join(dir, file), []byte(body), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				manifest := func(sbomFile string) string {
					m := "version: 1\nartifacts:\n  - id: a\n    sbom: " + sbomFile + "\n"
					if withContext {
						m += "    context: {file: context.json}\n"
					}
					return m + "gate:\n  mode: warn\n"
				}
				ctx := func(sbom []byte) {
					write("context.json", fmt.Sprintf(`{"contextVersion":1,"artifacts":[{"id":"a","sbom":{"sha256":"%s"},"source":{"repository":"https://code.example/a"}}]}`, index.SHA256Bytes(sbom)))
				}
				write("in1.json", in)
				write("rio1.yaml", manifest("in1.json"))
				if withContext {
					ctx([]byte(in))
				}
				first := normalizeOnce(t, dir, "rio1.yaml", "out1")
				if n := rioEntries(t, decode(t, first)); n != 1 {
					t.Fatalf("first run: %d rio entries", n)
				}

				write("in2.json", string(first))
				write("rio2.yaml", manifest("in2.json"))
				if withContext {
					ctx(first)
				}
				second := normalizeOnce(t, dir, "rio2.yaml", "out2")
				if n := rioEntries(t, decode(t, second)); n != 1 {
					t.Fatalf("second run: %d rio entries, want 1", n)
				}
			})
		}
	}
}
