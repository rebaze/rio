package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestArtifactSetsDemoFixtures(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(filepath.Join("..", "..", "tools", "demo-artifact-sets"))); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		manifest string
		ids      []string
	}{
		{"explicit-only.yaml", []string{"desktop"}},
		{"sets-only.yaml", []string{"billing-server", "orders-server"}},
		{"rio.yaml", []string{"desktop", "billing-server", "orders-server"}},
	} {
		rows := setRows(t, rio(t, dir, "plan", "--manifest", tc.manifest, "--json"))
		if len(rows) != len(tc.ids) {
			t.Fatal(rows)
		}
		for i, id := range tc.ids {
			if rows[i].(map[string]any)["id"] != id {
				t.Fatal(rows)
			}
		}
		requireExit(t, rio(t, dir, "normalize", "--manifest", tc.manifest, "--out", tc.manifest+"-out", "--gate", "fail"), ExitOK)
	}
	requireExit(t, rio(t, dir, "normalize", "--manifest", "overlap.yaml", "--out", "refused"), ExitUsage)
	if _, err := os.Stat(filepath.Join(dir, "refused")); !os.IsNotExist(err) {
		t.Fatal("overlap wrote output")
	}
}

func TestArtifactSetsPlanConsumer(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("plan consumer requires Python 3")
	}
	tool, err := filepath.Abs(filepath.Join("..", "..", "tools", "build-p2-table.py"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	setWrite(t, dir, "rio.yaml", "version: 1\n"+setDeclaration+"    transforms: [{repair-purl: {ecosystem: p2, table: mapping.json}}]\n")
	for _, id := range []string{"a-server", "b-server"} {
		setModule(t, dir, "services/"+id)
		setWrite(t, dir, "services/"+id+"/target/bom.json", strings.ReplaceAll(setBOM, `"pkg:maven/example/dep@2"`, `"pkg:p2/com.example.`+id+`@2?classifier=osgi.bundle"`))
	}
	plan := rio(t, dir, "plan", "--json")
	requireExit(t, plan, ExitOK)
	setWrite(t, dir, "plan.json", plan.stdout)
	cmd := exec.Command(python, tool, "--plan", filepath.Join(dir, "plan.json"), "--offline", "--cache", filepath.Join(dir, "cache"))
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("consumer: %v\n%s", err, output)
	}
	for _, id := range []string{"a-server", "b-server"} {
		if !strings.Contains(string(output), id) {
			t.Fatalf("consumer missed %s: %s", id, output)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "mapping.json")); err != nil {
		t.Fatal(err)
	}
}
