package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the public files with the same CLI path the installed-binary runner uses.
func TestContextDemoFixtures(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(filepath.Join("..", "..", "tools", "demo-context"))); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "context.json"), filepath.Join(dir, "saved-context.json")); err != nil {
		t.Fatal(err)
	}
	requireExit(t, rio(t, dir, "plan", "--manifest", "rio.yaml", "--json"), ExitOK)
	if err := os.Rename(filepath.Join(dir, "saved-context.json"), filepath.Join(dir, "context.json")); err != nil {
		t.Fatal(err)
	}
	r := rio(t, dir, "normalize", "--manifest", "rio.yaml", "--out", "normalized", "--gate", "fail", "--attest")
	requireExit(t, r, ExitOK)
	index := readFile(t, dir, "normalized", "index.json")
	rows := decode(t, index)["artifacts"].([]any)
	contextBytes := readFile(t, dir, "context.json")
	for i, tc := range []struct{ id, repo, buildURL, workspace string }{
		{"console", "https://code.example.org/widgets/console", "https://ci.example.org/widgets/runs/42", "clean"},
		{"agent", "https://code.example.org/agents/agent", "https://ci.example.org/agents/runs/7", "unknown"},
	} {
		input := decode(t, readFile(t, dir, "inputs", tc.id+".cdx.json"))
		output := decode(t, readFile(t, dir, "normalized", tc.id+".cdx.json"))
		inMeta := input["metadata"].(map[string]any)
		outMeta := output["metadata"].(map[string]any)
		if outMeta["timestamp"] != inMeta["timestamp"] || !bytes.Equal(mustJSON(t, input["components"]), mustJSON(t, output["components"])) {
			t.Fatalf("%s changed original timestamp or third-party components", tc.id)
		}
		tools := outMeta["tools"].(map[string]any)["components"].([]any)
		if !bytes.Equal(mustJSON(t, inMeta["tools"].(map[string]any)["components"].([]any)[0]), mustJSON(t, tools[0])) {
			t.Fatalf("%s changed original generator", tc.id)
		}
		refs := outMeta["component"].(map[string]any)["externalReferences"].([]any)
		if !strings.Contains(string(mustJSON(t, refs)), tc.repo) || !strings.Contains(string(mustJSON(t, refs)), tc.buildURL) || strings.Contains(string(mustJSON(t, refs)), "code.example.org/"+map[string]string{"console": "agents/agent", "agent": "widgets/console"}[tc.id]) {
			t.Fatalf("%s source refs mixed: %v", tc.id, refs)
		}
		claims := properties(t, output)["rebaze:normalize:context"]
		if len(claims) != 1 {
			t.Fatalf("%s context property count %d", tc.id, len(claims))
		}
		var claim map[string]any
		if err := json.Unmarshal([]byte(claims[0]), &claim); err != nil {
			t.Fatal(err)
		}
		if claim["effective"].(map[string]any)["source"].(map[string]any)["workspace"] != tc.workspace {
			t.Fatalf("%s workspace claim: %v", tc.id, claim)
		}
		if claim["selector"] != fmt.Sprintf("/artifacts/%d", i) || claim["assertion"] != "producer" || claim["file"].(map[string]any)["sha256"] != fmt.Sprintf("%x", sha256.Sum256(contextBytes)) || claim["effective"].(map[string]any)["sbom"].(map[string]any)["sha256"] != fmt.Sprintf("%x", sha256.Sum256(readFile(t, dir, "inputs", tc.id+".cdx.json"))) {
			t.Fatalf("%s wrong context provenance: %v", tc.id, claim)
		}
		if tc.workspace == "unknown" && !strings.Contains(string(mustJSON(t, claim["defaulted"])), "source.workspace") {
			t.Fatal("omitted workspace was not marked defaulted")
		}
		indexed := rows[i].(map[string]any)["context"]
		statement := decode(t, readFile(t, dir, "normalized", tc.id+".intoto.json"))["predicate"].(map[string]any)["artifact"].(map[string]any)["context"]
		if !bytes.Equal(mustJSON(t, claim), mustJSON(t, indexed)) || !bytes.Equal(mustJSON(t, claim), mustJSON(t, statement)) {
			t.Fatalf("%s context property, index and statement disagree", tc.id)
		}
		if tc.id == "console" && !strings.Contains(string(mustJSON(t, outMeta["lifecycles"])), "build") {
			t.Fatal("supplied lifecycle not applied")
		}
	}
	requireExit(t, rio(t, dir, "normalize", "--manifest", "rio.yaml", "--out", "normalized", "--gate", "fail", "--attest"), ExitOK)
	if !bytes.Equal(index, readFile(t, dir, "normalized", "index.json")) {
		t.Fatal("same inputs changed index")
	}
	for _, tc := range []struct{ manifest, want string }{
		{"stale.yaml", "sha256"}, {"missing.yaml", "build.url"}, {"conflict.yaml", "source.revision"},
	} {
		r := rio(t, dir, "normalize", "--manifest", tc.manifest, "--out", "refused")
		if r.exit != ExitUsage || !strings.Contains(r.stderr, tc.want) {
			t.Fatalf("%s exit=%d diagnostic=%s", tc.manifest, r.exit, r.stderr)
		}
		if _, err := os.Stat(filepath.Join(dir, "refused")); !os.IsNotExist(err) {
			t.Fatal("refusal wrote output")
		}
	}
	r = rio(t, dir, "normalize", "--manifest", "replace.yaml", "--out", "replaced")
	requireExit(t, r, ExitOK)
	claim := decode(t, readFile(t, dir, "replaced", "index.json"))["artifacts"].([]any)[0].(map[string]any)["context"].(map[string]any)
	effective := claim["effective"].(map[string]any)
	if effective["source"].(map[string]any)["workspace"] != "unknown" {
		t.Fatal("clean workspace inherited")
	}
	if _, exists := effective["build"].(map[string]any)["id"]; exists {
		t.Fatal("old build ID inherited")
	}
	changes := map[string]map[string]any{}
	for _, value := range claim["changes"].([]any) {
		change := value.(map[string]any)
		changes[change["field"].(string)] = change
	}
	for field, before := range map[string]string{
		"source.revision":  strings.Repeat("a", 40),
		"source.workspace": "clean",
		"build.id":         "old-run",
	} {
		change := changes[field]
		if change == nil || change["before"] != before || change["override"] != true {
			t.Fatalf("%s lacks explicit before/override audit: %v", field, change)
		}
		if field == "build.id" && change["after"] != nil {
			t.Fatalf("build ID was not removed: %v", change)
		}
	}
	t.Run("POSIX replacement checker", func(t *testing.T) {
		for _, command := range []string{"sh", "sed", "grep"} {
			if _, err := exec.LookPath(command); err != nil {
				t.Skipf("replacement checker requires %s: %v", command, err)
			}
		}
		check := filepath.Join(dir, "check-replacement.sh")
		replacementIndex := filepath.Join(dir, "replaced", "index.json")
		if output, err := exec.Command("sh", check, replacementIndex).CombinedOutput(); err != nil {
			t.Fatalf("public replacement check rejected valid output: %s: %v", output, err)
		}
		good := readFile(t, replacementIndex)
		for _, tc := range []struct{ name, old, new string }{
			{"wrong artifact ID", "\"effective\": {\n          \"id\": \"console\"", "\"effective\": {\n          \"id\": \"other\""},
			{"inherited build ID", "\"build\": {\n            \"url\"", "\"build\": {\n            \"id\": \"old-run\",\n            \"url\""},
			{"different build ID", "\"build\": {\n            \"url\"", "\"build\": {\n            \"id\": \"new-run\",\n            \"url\""},
			{"wrong revision", `"revision": "` + strings.Repeat("1", 40) + `"`, `"revision": "` + strings.Repeat("2", 40) + `"`},
			{"wrong workspace", `"workspace": "unknown"`, `"workspace": "clean"`},
			{"missing removal audit", "\"before\": \"old-run\",\n            \"after\": null", "\"before\": \"old-run\",\n            \"after\": \"old-run\""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				corrupted := bytes.Replace(good, []byte(tc.old), []byte(tc.new), 1)
				if bytes.Equal(corrupted, good) {
					t.Fatalf("test did not corrupt %s", tc.name)
				}
				path := filepath.Join(dir, "corrupted-index.json")
				if err := os.WriteFile(path, corrupted, 0o644); err != nil {
					t.Fatal(err)
				}
				if output, err := exec.Command("sh", check, path).CombinedOutput(); err == nil {
					t.Fatalf("public replacement check accepted %s: %s", tc.name, output)
				}
			})
		}
	})
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
