package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/rebaze/rio/internal/index"
)

// rcpProject copies testdata/rcp into a working directory: a manifest, the
// SBOM its glob resolves to, and the mapping table it names. It is the fixture
// §11 already uses, so plan and normalize are described against one repository
// rather than two that can drift.
func rcpProject(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	entries, err := os.ReadDir(filepath.Join("..", "..", "testdata", "rcp"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "rcp", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// The plan reports the manifest directory as the process sees it once it
	// is in it, and on macOS the temporary directory is reached through a
	// symlink. Resolving here means a test compares two spellings of the same
	// directory rather than two directories.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

// stableDir rewrites the one absolute path a plan carries, so the golden file
// is about the plan rather than about the machine that ran the test.
func stableDir(t *testing.T, out []byte, dir string) []byte {
	t.Helper()

	quoted, err := json.Marshal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, quoted) {
		t.Fatalf("the plan does not carry the manifest directory %s:\n%s", quoted, out)
	}
	return bytes.ReplaceAll(out, quoted, []byte(`"<manifest dir>"`))
}

func TestPlanJSON(t *testing.T) {
	dir := rcpProject(t)
	r := rio(t, dir, "plan", "--json")
	requireExit(t, r, ExitOK)

	golden(t, "plan.json", stableDir(t, []byte(r.stdout), dir))
}

func TestPlanHumanOutput(t *testing.T) {
	dir := rcpProject(t)
	r := rio(t, dir, "plan")
	requireExit(t, r, ExitOK)

	want := "manifest  rio.yaml (sha256 " + manifestDigest(t, dir)[:12] + "…)\n" +
		"\n" +
		"rcp-example\n" +
		"  read   tycho-rcp.cdx.json\n" +
		"  write  target/rio/rcp-example.cdx.json\n" +
		"  repair-purl  ecosystem p2  table p2-maven.json\n" +
		"\n" +
		"rcp-example-unmapped\n" +
		"  read   tycho-rcp.cdx.json\n" +
		"  write  target/rio/rcp-example-unmapped.cdx.json\n" +
		"  no transforms\n" +
		"\n" +
		"gate  require name, version, purl\n"
	if r.stdout != want {
		t.Fatalf("stdout =\n%s\nwant\n%s", r.stdout, want)
	}
	if r.stderr != "" {
		t.Fatalf("plan wrote to stderr:\n%s", r.stderr)
	}
}

// The property everything else rests on, and precisely what a refactor that
// moved transform construction earlier would silently break: the mapping table
// is produced FROM the plan, so the first run in a repository has none.
func TestPlanSucceedsWithNoMappingTableOnDisk(t *testing.T) {
	dir := rcpProject(t)
	if err := os.Remove(filepath.Join(dir, "p2-maven.json")); err != nil {
		t.Fatal(err)
	}

	// normalize is the control: nothing about the transform itself has
	// softened, only what plan needs from it.
	requireExit(t, rio(t, dir, "normalize"), ExitUsage)

	r := rio(t, dir, "plan", "--json")
	requireExit(t, r, ExitOK)

	got := decodePlan(t, r.stdout)
	artifacts, _ := got["artifacts"].([]any)
	first, _ := artifacts[0].(map[string]any)
	transforms, _ := first["transforms"].([]any)
	entry, _ := transforms[0].(map[string]any)
	if entry["table"] != "p2-maven.json" {
		t.Fatalf("transforms[0].table = %v, want the path the manifest names", entry["table"])
	}
}

// A human is told, on the line that names the table, because normalize will
// hard-fail on it.
func TestPlanSaysWhenTheTableIsNotThereYet(t *testing.T) {
	dir := rcpProject(t)
	if err := os.Remove(filepath.Join(dir, "p2-maven.json")); err != nil {
		t.Fatal(err)
	}

	r := rio(t, dir, "plan")
	requireExit(t, r, ExitOK)
	if !strings.Contains(r.stdout, "table p2-maven.json (not there yet") {
		t.Fatalf("plan does not flag the missing table:\n%s", r.stdout)
	}

	// And says nothing of the sort once it exists.
	dir = rcpProject(t)
	r = rio(t, dir, "plan")
	requireExit(t, r, ExitOK)
	if strings.Contains(r.stdout, "not there yet") {
		t.Fatalf("plan flags a table that is right there:\n%s", r.stdout)
	}
}

// Two descriptions of "which file did rio read" that a consumer joins against
// the same directory. They must not drift.
func TestPlanInputPathsAgreeWithTheIndex(t *testing.T) {
	dir := rcpProject(t)

	r := rio(t, dir, "plan", "--json")
	requireExit(t, r, ExitOK)
	requireExit(t, rio(t, dir, "normalize"), ExitOK)

	fromPlan := map[string]string{}
	artifacts, _ := decodePlan(t, r.stdout)["artifacts"].([]any)
	for _, entry := range artifacts {
		a, _ := entry.(map[string]any)
		input, _ := a["input"].(map[string]any)
		id, _ := a["id"].(string)
		fromPlan[id], _ = input["path"].(string)
	}

	fromIndex := map[string]string{}
	indexed, _ := indexOf(t, run{dir: dir}, filepath.Join("target", "rio"))["artifacts"].([]any)
	for _, entry := range indexed {
		a, _ := entry.(map[string]any)
		input, _ := a["input"].(map[string]any)
		id, _ := a["id"].(string)
		fromIndex[id], _ = input["path"].(string)
	}

	if diff := cmp.Diff(fromIndex, fromPlan); diff != "" {
		t.Fatalf("plan and index.json disagree about the inputs (-index +plan):\n%s", diff)
	}
	if len(fromPlan) == 0 {
		t.Fatal("no artifacts compared")
	}
}

// Output paths agree too: both are relative to the directory rio writes into,
// so a consumer that has one can find the other.
func TestPlanOutputPathsAgreeWithTheIndex(t *testing.T) {
	dir := rcpProject(t)

	r := rio(t, dir, "plan", "--json")
	requireExit(t, r, ExitOK)
	requireExit(t, rio(t, dir, "normalize"), ExitOK)

	artifacts, _ := decodePlan(t, r.stdout)["artifacts"].([]any)
	indexed, _ := indexOf(t, run{dir: dir}, filepath.Join("target", "rio"))["artifacts"].([]any)
	if len(artifacts) != len(indexed) {
		t.Fatalf("plan describes %d artifacts, the index records %d", len(artifacts), len(indexed))
	}
	for i := range artifacts {
		a, _ := artifacts[i].(map[string]any)
		b, _ := indexed[i].(map[string]any)
		planOut, _ := a["output"].(map[string]any)
		indexOut, _ := b["output"].(map[string]any)
		if planOut["path"] != indexOut["path"] {
			t.Fatalf("artifact %v: plan output %v, index output %v", a["id"], planOut["path"], indexOut["path"])
		}
	}
}

// The built-in table travels with the plan so a generated override can stay a
// delta over it.
func TestPlanCarriesTheBuiltInTable(t *testing.T) {
	dir := rcpProject(t)
	r := rio(t, dir, "plan", "--json")
	requireExit(t, r, ExitOK)

	table, _ := decodePlan(t, r.stdout)["builtinTable"].(map[string]any)
	entry, _ := table["com.google.gson"].(map[string]any)
	if entry["groupId"] != "com.google.code.gson" || entry["artifactId"] != "gson" {
		t.Fatalf("builtinTable[com.google.gson] = %v", entry)
	}
	if len(table) < 9 {
		t.Fatalf("builtinTable has %d entries, want the shipped asset", len(table))
	}
}

// The manifest directory is the one absolute path a plan carries, and it is
// there so a consumer can join the relative ones against it rather than guess.
func TestPlanManifestBlockIsJoinable(t *testing.T) {
	dir := rcpProject(t)

	// Reached three ways, the block must name the same file each time.
	for _, args := range [][]string{
		{"plan", "--json"},
		{"plan", "--json", "--manifest", "rio.yaml"},
		{"plan", "--json", "--manifest", filepath.Join(dir, "rio.yaml")},
	} {
		r := rio(t, dir, args...)
		requireExit(t, r, ExitOK)

		block, _ := decodePlan(t, r.stdout)["manifest"].(map[string]any)
		if block["path"] != "rio.yaml" {
			t.Fatalf("%v: manifest.path = %v, want %q", args, block["path"], "rio.yaml")
		}
		base, _ := block["dir"].(string)
		if !filepath.IsAbs(base) {
			t.Fatalf("%v: manifest.dir = %q, want an absolute path", args, base)
		}
		joined := filepath.Join(base, block["path"].(string))
		if _, err := os.Stat(joined); err != nil {
			t.Fatalf("%v: manifest.dir + manifest.path is not the manifest: %v", args, err)
		}
		if block["sha256"] != manifestDigest(t, dir) {
			t.Fatalf("%v: manifest.sha256 = %v", args, block["sha256"])
		}
	}
}

// plan writes nothing, so it cannot be the step that creates target/rio.
func TestPlanWritesNothing(t *testing.T) {
	dir := rcpProject(t)
	before := treeOf(t, dir)

	requireExit(t, rio(t, dir, "plan"), ExitOK)
	requireExit(t, rio(t, dir, "plan", "--json"), ExitOK)

	if diff := cmp.Diff(before, treeOf(t, dir)); diff != "" {
		t.Fatalf("plan touched the working directory (-before +after):\n%s", diff)
	}
}

// Every diagnostic normalize raises before it reads an SBOM, plan raises too:
// a plan that succeeded where normalize fails would describe a run that cannot
// happen (§10).
func TestPlanExitTwoConditions(t *testing.T) {
	cases := []struct {
		name     string
		manifest string
		args     []string
		wants    []string
	}{
		{
			name:  "missing manifest",
			args:  []string{"plan", "--manifest", "absent.yaml"},
			wants: []string{"absent.yaml"},
		},
		{
			name:     "version is not 1",
			manifest: "version: 2\nartifacts:\n  - id: a\n    sbom: \"tycho-rcp.cdx.json\"\n",
			wants:    []string{"version"},
		},
		{
			name:     "unknown manifest key",
			manifest: "version: 1\nartifacts:\n  - id: a\n    sbom: \"tycho-rcp.cdx.json\"\noutputs: {}\n",
			wants:    []string{"outputs"},
		},
		{
			name:     "glob matches zero files",
			manifest: "version: 1\nartifacts:\n  - id: a\n    sbom: \"nothing/*.json\"\n",
			wants:    []string{"a", "nothing/*.json"},
		},
		{
			name:     "glob matches several files",
			manifest: "version: 1\nartifacts:\n  - id: a\n    sbom: \"*.json\"\n",
			wants:    []string{"p2-maven.json", "tycho-rcp.cdx.json"},
		},
		{
			name:     "unknown transform",
			manifest: "version: 1\nartifacts:\n  - id: a\n    sbom: \"tycho-rcp.cdx.json\"\n    transforms:\n      - repair-everything: {}\n",
			wants:    []string{"repair-everything", "repair-purl"},
		},
		{
			name:     "unknown transform ecosystem",
			manifest: "version: 1\nartifacts:\n  - id: a\n    sbom: \"tycho-rcp.cdx.json\"\n    transforms:\n      - repair-purl:\n          ecosystem: npm\n",
			wants:    []string{"npm"},
		},
		{
			name:     "unknown transform option",
			manifest: "version: 1\nartifacts:\n  - id: a\n    sbom: \"tycho-rcp.cdx.json\"\n    transforms:\n      - repair-purl:\n          ecosystem: p2\n          tabel: p2-maven.json\n",
			wants:    []string{"tabel"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := rcpProject(t)
			switch {
			case tc.name == "missing manifest":
				if err := os.Remove(filepath.Join(dir, "rio.yaml")); err != nil {
					t.Fatal(err)
				}
			case tc.manifest != "":
				if err := os.WriteFile(filepath.Join(dir, "rio.yaml"), []byte(tc.manifest), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			args := tc.args
			if args == nil {
				args = []string{"plan"}
			}
			r := rio(t, dir, args...)
			requireExit(t, r, ExitUsage)
			requireStderr(t, r, tc.wants...)

			// The same manifest, the same failure, through --json.
			requireExit(t, rio(t, dir, append(args, "--json")...), ExitUsage)
		})
	}
}

// Nothing partial reaches stdout when a later artifact is the broken one: a
// consumer parses stdout as one document.
func TestPlanPrintsNothingWhenALaterArtifactFails(t *testing.T) {
	dir := rcpProject(t)
	manifest := "version: 1\nartifacts:\n" +
		"  - id: good\n    sbom: \"tycho-rcp.cdx.json\"\n" +
		"  - id: bad\n    sbom: \"nothing/*.json\"\n"
	if err := os.WriteFile(filepath.Join(dir, "rio.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	r := rio(t, dir, "plan", "--json")
	requireExit(t, r, ExitUsage)
	if r.stdout != "" {
		t.Fatalf("plan printed a partial document:\n%s", r.stdout)
	}
}

func TestPlanTakesNoArguments(t *testing.T) {
	dir := rcpProject(t)
	if r := rio(t, dir, "plan", "extra"); r.exit != ExitUsage {
		t.Fatalf("exit = %d, want %d", r.exit, ExitUsage)
	}
}

// --quiet drops the per artifact blocks, exactly as it does for normalize, and
// leaves what frames them. It has no say over --json, which is a contract.
func TestPlanQuiet(t *testing.T) {
	dir := rcpProject(t)

	r := rio(t, dir, "plan", "--quiet")
	requireExit(t, r, ExitOK)
	if strings.Contains(r.stdout, "rcp-example") {
		t.Fatalf("--quiet still printed a per artifact block:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "manifest  rio.yaml") || !strings.Contains(r.stdout, "gate  require") {
		t.Fatalf("--quiet dropped more than the artifacts:\n%s", r.stdout)
	}

	quiet := rio(t, dir, "plan", "--json", "--quiet")
	loud := rio(t, dir, "plan", "--json")
	requireExit(t, quiet, ExitOK)
	if quiet.stdout != loud.stdout {
		t.Fatal("--quiet changed the JSON contract")
	}
}

// An explicitly empty gate.require is the empty subset, not a missing key, and
// the human line has to read as a decision.
func TestPlanReportsAnEmptyGate(t *testing.T) {
	dir := rcpProject(t)
	manifest := "version: 1\nartifacts:\n  - id: a\n    sbom: \"tycho-rcp.cdx.json\"\ngate:\n  require: []\n"
	if err := os.WriteFile(filepath.Join(dir, "rio.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	r := rio(t, dir, "plan")
	requireExit(t, r, ExitOK)
	if !strings.Contains(r.stdout, "gate  require nothing\n") {
		t.Fatalf("stdout =\n%s", r.stdout)
	}

	j := rio(t, dir, "plan", "--json")
	requireExit(t, j, ExitOK)
	gate, _ := decodePlan(t, j.stdout)["gate"].(map[string]any)
	require, ok := gate["require"].([]any)
	if !ok || len(require) != 0 {
		t.Fatalf("gate.require = %v, want an empty array", gate["require"])
	}
}

// A manifest that overrides a scope key must produce a plan carrying that same
// key, or a tool would harvest under one filter and rio read back under
// another.
func TestPlanCarriesOverriddenScopeKeys(t *testing.T) {
	dir := rcpProject(t)
	manifest := "version: 1\nartifacts:\n  - id: a\n    sbom: \"tycho-rcp.cdx.json\"\n" +
		"    transforms:\n      - repair-purl:\n          ecosystem: p2\n" +
		"          table: p2-maven.json\n          groupPrefix: \"acme.\"\n"
	if err := os.WriteFile(filepath.Join(dir, "rio.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	r := rio(t, dir, "plan", "--json")
	requireExit(t, r, ExitOK)

	artifacts, _ := decodePlan(t, r.stdout)["artifacts"].([]any)
	first, _ := artifacts[0].(map[string]any)
	transforms, _ := first["transforms"].([]any)
	entry, _ := transforms[0].(map[string]any)

	want := map[string]any{
		"name":               "repair-purl",
		"ecosystem":          "p2",
		"table":              "p2-maven.json",
		"groupPrefix":        "acme.",
		"classifier":         "osgi.bundle",
		"syntheticNamespace": "p2.eclipse.plugin",
	}
	if diff := cmp.Diff(want, entry); diff != "" {
		t.Fatalf("transforms[0] (-want +got):\n%s", diff)
	}

	// And a human sees the override rather than having to diff two defaults.
	h := rio(t, dir, "plan")
	requireExit(t, h, ExitOK)
	if !strings.Contains(h.stdout, "groupPrefix acme.") {
		t.Fatalf("stdout does not show the override:\n%s", h.stdout)
	}
}

// The plan is read by a program, so two runs over the same manifest have to
// produce the same bytes (§7).
func TestPlanIsDeterministic(t *testing.T) {
	dir := rcpProject(t)

	first := rio(t, dir, "plan", "--json")
	requireExit(t, first, ExitOK)
	for i := 0; i < 3; i++ {
		again := rio(t, dir, "plan", "--json")
		requireExit(t, again, ExitOK)
		if again.stdout != first.stdout {
			t.Fatal("two plans over the same manifest differ")
		}
	}
}

func decodePlan(t *testing.T, out string) map[string]any {
	t.Helper()

	got := decode(t, []byte(out))
	if got["planVersion"].(json.Number).String() != "1" {
		t.Fatalf("planVersion = %v, want 1", got["planVersion"])
	}
	return got
}

func manifestDigest(t *testing.T, dir string) string {
	t.Helper()
	return digestOf(t, filepath.Join(dir, "rio.yaml"))
}

func digestOf(t *testing.T, path string) string {
	t.Helper()
	sum, err := index.SHA256File(path)
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

// treeOf lists every file under dir with its digest, so a test can assert that
// a command left the working directory exactly as it found it.
func treeOf(t *testing.T, dir string) map[string]string {
	t.Helper()

	out := map[string]string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = digestOf(t, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
