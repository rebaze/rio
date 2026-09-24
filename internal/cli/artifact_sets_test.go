package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/index"
)

const setBOM = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"original-subject","version":"1"}},"components":[{"type":"library","name":"dep","version":"2","purl":"pkg:maven/example/dep@2"}]}`
const setDeclaration = `artifactSets:
  - modules: services/**/*server/pom.xml
    sbom: target/*.json
    idFrom: module-directory
`

func setWrite(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}
func setModule(t *testing.T, dir, name string) {
	t.Helper()
	setWrite(t, dir, name+"/pom.xml", "<project/>")
	setWrite(t, dir, name+"/target/bom.json", setBOM)
}
func setRows(t *testing.T, r run) []any {
	t.Helper()
	requireExit(t, r, ExitOK)
	return decode(t, []byte(r.stdout))["artifacts"].([]any)
}

func TestArtifactSetsPlanNormalizeMembership(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo [literal] space")
	setWrite(t, dir, "rio.yaml", "version: 1\nartifacts: [{id: desktop, sbom: desktop.json}]\n"+setDeclaration)
	setWrite(t, dir, "desktop.json", setBOM)
	for _, m := range []string{"services/z-server", "services/group [special]/a-server", "services/web-client"} {
		setModule(t, dir, m)
	}
	// SBOM filename metacharacters must never become another glob after resolution.
	if err := os.Rename(filepath.Join(dir, "services/z-server/target/bom.json"), filepath.Join(dir, "services/z-server/target/bom[1].json")); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	rows := setRows(t, rio(t, other, "plan", "--manifest", filepath.Join(dir, "rio.yaml"), "--json"))
	wantIDs := []string{"desktop", "a-server", "z-server"}
	if len(rows) != len(wantIDs) {
		t.Fatal(rows)
	}
	requireExit(t, rio(t, dir, "normalize", "--out", "out", "--attest", "--gate", "fail"), ExitOK)
	idx := decode(t, readFile(t, dir, "out/index.json"))["artifacts"].([]any)
	for i, id := range wantIDs {
		p := rows[i].(map[string]any)
		a := idx[i].(map[string]any)
		if p["id"] != id || a["id"] != id || p["input"].(map[string]any)["path"] != a["input"].(map[string]any)["path"] {
			t.Fatalf("plan/index mismatch: %v %v", p, a)
		}
		if !reflect.DeepEqual(p["selection"], a["selection"]) {
			t.Fatal("selection differs")
		}
		stmt := decode(t, readFile(t, dir, "out", id+".intoto.json"))["predicate"].(map[string]any)["artifact"].(map[string]any)
		if !reflect.DeepEqual(stmt["selection"], a["selection"]) {
			t.Fatal("statement selection differs")
		}
		if i == 0 {
			if _, ok := a["selection"]; ok {
				t.Fatal("explicit selection present")
			}
			continue
		}
		module := map[string]string{"a-server": "services/group [special]/a-server", "z-server": "services/z-server"}[id]
		want := map[string]any{"version": decode(t, []byte(`{"n":1}`))["n"], "kind": "artifactSet", "source": "artifactSets[0]", "module": module, "marker": module + "/pom.xml"}
		if !reflect.DeepEqual(p["selection"], want) {
			t.Fatalf("selection %v want %v", p["selection"], want)
		}
		output := decode(t, readFile(t, dir, "out", id+".cdx.json"))
		if output["metadata"].(map[string]any)["component"].(map[string]any)["name"] != "original-subject" || !reflect.DeepEqual(output["components"], decode(t, []byte(setBOM))["components"]) {
			t.Fatal("directory identity changed SBOM inventory/subject")
		}
	}
	before := readFile(t, dir, "out/index.json")
	requireExit(t, rio(t, dir, "normalize", "--out", "out", "--attest", "--gate", "fail"), ExitOK)
	if !bytes.Equal(before, readFile(t, dir, "out/index.json")) {
		t.Fatal("nondeterministic index")
	}
	textPlan := rio(t, dir, "plan")
	requireExit(t, textPlan, ExitOK)
	if !strings.Contains(textPlan.stdout, "artifactSets[0]") || !strings.Contains(textPlan.stdout, "services/z-server") {
		t.Fatal(textPlan.stdout)
	}
	manifestBefore := readFile(t, dir, "rio.yaml")
	setModule(t, dir, "services/new-server")
	if rows := setRows(t, rio(t, dir, "plan", "--json")); len(rows) != 4 {
		t.Fatal(rows)
	}
	if err := os.Remove(filepath.Join(dir, "services/new-server/target/bom.json")); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"plan", "normalize"} {
		r := rio(t, dir, cmd, "--out", "refused")
		requireExit(t, r, ExitUsage)
		requireStderr(t, r, "artifactSets[0]", "services/new-server", "target/*.json")
	}
	if _, err := os.Stat(filepath.Join(dir, "refused")); !os.IsNotExist(err) {
		t.Fatal("failure wrote output")
	}
	if err := os.Remove(filepath.Join(dir, "services/new-server/pom.xml")); err != nil {
		t.Fatal(err)
	}
	requireExit(t, rio(t, dir, "normalize", "--out", "fresh"), ExitOK)
	if got := decode(t, readFile(t, dir, "fresh/index.json"))["artifacts"].([]any); len(got) != 3 {
		t.Fatal(got)
	}
	if !bytes.Equal(manifestBefore, readFile(t, dir, "rio.yaml")) {
		t.Fatal("manifest changed")
	}
}

func TestArtifactSetsRefuseAmbiguities(t *testing.T) {
	for _, tc := range []struct {
		name, extra, modules, want string
		setup                      func(*testing.T, string)
	}{
		{name: "two SBOMs", want: "matched 2", setup: func(t *testing.T, d string) { setWrite(t, d, "services/a-server/target/second.json", setBOM) }},
		{name: "invalid ID", modules: "services/Bad-server", want: "does not match"},
		{name: "same basename", modules: "services/nested/a-server", want: "ID"},
		{name: "explicit ID", extra: "artifacts: [{id: a-server, sbom: old.json}]\n", want: "artifacts[0]"},
		{name: "cross set", extra: "", want: "artifactSets[1]", setup: func(t *testing.T, d string) {
			setWrite(t, d, "rio.yaml", "version: 1\n"+setDeclaration+"  - {modules: services/*server/pom.xml, sbom: target/*.json, idFrom: module-directory}\n")
		}},
		{name: "physical SBOM", extra: "artifacts: [{id: old, sbom: old.json}]\n", want: "same physical SBOM", setup: func(t *testing.T, d string) {
			p := filepath.Join(d, "old.json")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(d, "services/a-server/target/bom.json"), p); err != nil {
				t.Skip(err)
			}
		}},
		{name: "alias root", want: "same physical", setup: func(t *testing.T, d string) {
			if err := os.Symlink(filepath.Join(d, "services/a-server"), filepath.Join(d, "services/alias-server")); err != nil {
				t.Skip(err)
			}
		}},
		{name: "excluded all", want: "no module roots", setup: func(t *testing.T, d string) {
			setWrite(t, d, "rio.yaml", "version: 1\n"+setDeclaration+"    exclude: ['**/pom.xml']\n")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			setWrite(t, dir, "rio.yaml", "version: 1\n"+tc.extra+setDeclaration)
			setWrite(t, dir, "old.json", setBOM)
			setModule(t, dir, "services/a-server")
			if tc.modules != "" {
				setModule(t, dir, tc.modules)
			}
			if tc.setup != nil {
				tc.setup(t, dir)
			}
			for _, cmd := range []string{"plan", "normalize"} {
				r := rio(t, dir, cmd, "--out", "refused")
				requireExit(t, r, ExitUsage)
				requireStderr(t, r, tc.want, "artifactSets[")
			}
			if _, err := os.Stat(filepath.Join(dir, "refused")); !os.IsNotExist(err) {
				t.Fatal("failure wrote output")
			}
		})
	}
}

func TestArtifactSetsSettings(t *testing.T) {
	dir := t.TempDir()
	setWrite(t, dir, "rio.yaml", `version: 1
enrichment: {producer: {name: Example}}
`+setDeclaration+`    enrichment: {subject: {group: example}}
    context: {file: context.json, require: [build.url]}
    transforms: [{repair-purl: {ecosystem: p2, table: mapping.json}}]
`)
	for _, id := range []string{"a-server", "b-server"} {
		setModule(t, dir, "services/"+id)
	}
	p := rio(t, dir, "plan", "--json")
	rows := setRows(t, p)
	for _, raw := range rows {
		a := raw.(map[string]any)
		if a["context"].(map[string]any)["file"] != "context.json" {
			t.Fatal(a)
		}
		fields := a["enrichment"].(map[string]any)["fields"].([]any)
		sources := string(mustJSON(t, fields))
		if !strings.Contains(sources, "artifactSets[0].enrichment.subject.group") || !strings.Contains(sources, "enrichment.producer.name") {
			t.Fatal(sources)
		}
	}
	setWrite(t, dir, "mapping.json", `{"schemaVersion":1,"entries":{}}`)
	var assertions []string
	for _, id := range []string{"a-server", "b-server"} {
		assertions = append(assertions, fmt.Sprintf(`{"id":%q,"sbom":{"sha256":%q},"build":{"url":%q}}`, id, index.SHA256Bytes([]byte(setBOM)), "https://ci.example/"+id))
	}
	setWrite(t, dir, "context.json", `{"contextVersion":1,"artifacts":[`+strings.Join(assertions, ",")+`]}`)
	requireExit(t, rio(t, dir, "normalize", "--out", "out", "--attest"), ExitOK)
	for _, raw := range decode(t, readFile(t, dir, "out/index.json"))["artifacts"].([]any) {
		a := raw.(map[string]any)
		effective := a["context"].(map[string]any)["effective"].(map[string]any)
		if effective["id"] != a["id"] || effective["build"].(map[string]any)["url"] != "https://ci.example/"+a["id"].(string) {
			t.Fatal(a)
		}
		if !strings.Contains(string(mustJSON(t, a["enrichment"])), "artifactSets[0].enrichment.subject.group") {
			t.Fatal(a)
		}
	}
	setWrite(t, dir, "services/b-server/target/bom.json", setBOM+"\n")
	r := rio(t, dir, "normalize", "--out", "stale")
	requireExit(t, r, ExitUsage)
	requireStderr(t, r, "sha256")
	if _, err := os.Stat(filepath.Join(dir, "stale")); !os.IsNotExist(err) {
		t.Fatal("stale context wrote output")
	}
}

func TestArtifactSetsExclusionPrecedesSBOMAndExplicitOnlyOverlapRemainsValid(t *testing.T) {
	dir := t.TempDir()
	setModule(t, dir, "services/a-server")
	setWrite(t, dir, "services/excluded-server/pom.xml", "marker")
	setWrite(t, dir, "rio.yaml", "version: 1\n"+setDeclaration+"    exclude: [services/excluded-server/pom.xml]\n")
	if rows := setRows(t, rio(t, dir, "plan", "--json")); len(rows) != 1 {
		t.Fatal(rows)
	}
	setWrite(t, dir, "rio.yaml", "version: 1\nartifacts: [{id: one, sbom: services/a-server/target/bom.json}, {id: two, sbom: services/a-server/target/bom.json}]\n")
	requireExit(t, rio(t, dir, "normalize", "--out", "out"), ExitOK)
	if strings.Contains(string(readFile(t, dir, "out/index.json")), `"selection"`) {
		t.Fatal("legacy shape changed")
	}
}
