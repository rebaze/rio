package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestClientRecordDemoNormalizationContract(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join("..", "..", "tools", "demo-client-record")
	if err := os.CopyFS(dir, os.DirFS(source)); err != nil {
		t.Fatal("client demonstration missing", err)
	}
	requireExit(t, rio(t, dir, "normalize", "--gate", "fail"), ExitOK)
	idx := decode(t, readFile(t, dir, "target/rio/index.json"))
	artifacts := idx["artifacts"].([]any)
	if len(artifacts) != 2 {
		t.Fatal("two selected modules required")
	}
	for _, v := range artifacts {
		a := v.(map[string]any)
		spec := a["specVersion"].(map[string]any)
		if a["selection"] == nil || spec["input"] != "1.4" || spec["output"] != "1.6" || a["enrichment"] == nil {
			t.Fatal("demo lacks scope/uplift/enrichment", a)
		}
		tr := a["transforms"].([]any)[0].(map[string]any)
		if tr["applied"] != json.Number("2") || tr["unmapped"] != json.Number("1") {
			t.Fatal("demo lacks combined repair/unresolved evidence", tr)
		}
	}
}
