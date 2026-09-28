package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func recordRun(t *testing.T, args ...string) (int, map[string]any, string) {
	t.Helper()
	var out, err bytes.Buffer
	code := Main(append(args, "--json"), &out, &err)
	var m map[string]any
	dec := json.NewDecoder(&out)
	dec.UseNumber()
	if e := dec.Decode(&m); e != nil {
		t.Fatalf("missing JSON code=%d stdout=%q stderr=%q", code, out.String(), err.String())
	}
	var extra any
	if e := dec.Decode(&extra); e != io.EOF {
		t.Fatal("extra stdout")
	}
	return code, m, err.String()
}
func TestRecordPreservesProducerContextAndEnrichmentChanges(t *testing.T) {
	for _, example := range []string{"demo-context", "demo-enrichment"} {
		t.Run(example, func(t *testing.T) {
			manifest, e := filepath.Abs(filepath.Join("..", "..", "tools", example, "rio.yaml"))
			if e != nil {
				t.Fatal(e)
			}
			dir := t.TempDir()
			var stdout, stderr bytes.Buffer
			code := Main([]string{"normalize", "--manifest", manifest, "--out", dir, "--gate", "warn", "--attest"}, &stdout, &stderr)
			if code != 0 {
				t.Fatal("normalization fixture", code, stderr.String())
			}
			ip := filepath.Join(latestOutput(t, "", dir), "index.json")
			raw, _ := os.ReadFile(ip)
			if !bytes.Contains(raw, []byte(`"before": null`)) {
				t.Fatal("fixture lacks nullable producer changes")
			}
			out := filepath.Join(latestOutput(t, "", dir), "record.json")
			compact := readFile(t, out)
			if !bytes.Contains(compact, []byte(`"before": null`)) {
				t.Fatal("compact receipt lost nullable changes")
			}
			code, r, err := recordRun(t, "record", "inspect", "--file", out)
			if code != 0 {
				t.Fatal("valid producer context cannot be inspected", code, r, err)
			}
		})
	}
}
