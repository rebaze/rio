package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The first-run demo promises one visible repair without a project build or mapping table.
func TestRepairDemoFirstResult(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(filepath.Join("..", "..", "tools", "demo-repair"))); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, dir, "bom.json")
	requireExit(t, rio(t, dir, "normalize", "--out", "out", "--gate", "fail"), ExitOK)
	output := decode(t, readFile(t, dir, "out", "sample.cdx.json"))
	got := purls(t, output)
	if len(got) != 1 || got[0] != "pkg:maven/com.google.code.gson/gson@2.8.9" {
		t.Fatalf("unexpected first result: %v", got)
	}
	if !bytes.Equal(before, readFile(t, dir, "bom.json")) {
		t.Fatal("demo changed the input")
	}
	if !strings.Contains(string(readFile(t, dir, "out", "sample.cdx.json")), "rule=repair-purl/p2 | from=pkg:p2/com.google.gson@2.8.9?classifier=osgi.bundle | to=pkg:maven/com.google.code.gson/gson@2.8.9") {
		t.Fatal("repair audit does not preserve the before/after URLs")
	}
	rows := decode(t, readFile(t, dir, "out", "index.json"))["artifacts"].([]any)
	if len(rows) != 1 {
		t.Fatal(rows)
	}
	row := rows[0].(map[string]any)
	if row["id"] != "sample" || row["gate"] != "ok" {
		t.Fatal(row)
	}
	transforms := row["transforms"].([]any)
	if len(transforms) != 1 || transforms[0].(map[string]any)["applied"] != json.Number("1") || transforms[0].(map[string]any)["unmapped"] != json.Number("0") {
		t.Fatal(transforms)
	}
}
