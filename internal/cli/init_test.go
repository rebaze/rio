package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitFirstLocalReceipt(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "target"), 0o755); err != nil {
		t.Fatal(err)
	}
	input := readFile(t, "..", "..", "tools", "demo-use-case", "inputs", "bom.json")
	if err := os.WriteFile(filepath.Join(dir, "target", "bom.json"), input, 0o644); err != nil {
		t.Fatal(err)
	}
	preview := rio(t, dir, "init")
	requireExit(t, preview, ExitOK)
	if sample := string(readFile(t, "..", "..", "tools", "demo-first-run", "rio.yaml")); preview.stdout != sample {
		t.Fatalf("preview differs from documented sample:\n%s", preview.stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, "rio.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preview wrote manifest: %v", err)
	}
	requireExit(t, rio(t, dir, "init", "--write"), ExitOK)
	if got := string(readFile(t, dir, "rio.yaml")); got != preview.stdout {
		t.Fatalf("saved manifest differs from preview: %s", got)
	}
	plan := rio(t, dir, "plan", "--json")
	requireExit(t, plan, ExitOK)
	if !strings.Contains(plan.stdout, "target/bom.json") {
		t.Fatal(plan.stdout)
	}
	run := rio(t, dir, "--skip-delivery", "--json")
	requireExit(t, run, ExitOK)
	receipt := decode(t, []byte(run.stdout))["receipt"].(map[string]any)["path"].(string)
	requireExit(t, rio(t, dir, "record", "inspect", "--file", receipt), ExitOK)
}

func TestInitProtectionAndCustomPath(t *testing.T) {
	dir := project(t, "# keep this manifest\n", "plain-maven.cdx.json")
	requireExit(t, rio(t, dir, "init", "--write", "--sbom", "in/plain-maven.cdx.json"), ExitUsage)
	if got := string(readFile(t, dir, "rio.yaml")); got != "# keep this manifest\n" {
		t.Fatal(got)
	}
	input := "quoted # path.cdx.json"
	if err := os.Rename(filepath.Join(dir, "in", "plain-maven.cdx.json"), filepath.Join(dir, "in", input)); err != nil {
		t.Fatal(err)
	}
	requireExit(t, rio(t, dir, "init", "--write", "--manifest", "in/custom.yaml", "--sbom", input), ExitOK)
	requireExit(t, rio(t, dir, "plan", "--manifest", "in/custom.yaml"), ExitOK)
	for _, pattern := range []string{"missing.json", "rio.yaml"} {
		requireExit(t, rio(t, dir, "init", "--write", "--sbom", pattern, "--manifest", "new.yaml"), ExitUsage)
		if _, err := os.Stat(filepath.Join(dir, "new.yaml")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
}
