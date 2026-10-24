package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/rebaze/rio/internal/buildcontext"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/sbom"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/rebaze/rio/internal/index"
	"github.com/rebaze/rio/internal/receipt"
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
	requireNoNormalizedOutputs(t, filepath.Join(dir, "target"))
	writeContextFile(t, dir, one, two)
	requireExit(t, rio(t, dir, "normalize", "--attest"), ExitOK)
	idx := decode(t, readFile(t, latestOutput(t, dir, "target/rio"), "index.json"))
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
		out := decode(t, readFile(t, latestOutput(t, dir, "target/rio"), id+".cdx.json"))
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
		stmt := decode(t, readFile(t, latestOutput(t, dir, "target/rio"), id+".intoto.json"))
		predicate := stmt["predicate"].(map[string]any)
		artifact := predicate["artifact"].(map[string]any)
		y, _ := json.Marshal(artifact["context"])
		if !bytes.Equal(x, y) {
			t.Fatal("statement context differs")
		}
	}
	first := readFile(t, latestOutput(t, dir, "target/rio"), "index.json")
	requireExit(t, rio(t, dir, "normalize", "--attest"), ExitOK)
	if !bytes.Equal(first, readFile(t, latestOutput(t, dir, "target/rio"), "index.json")) {
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
	requireNoNormalizedOutputs(t, filepath.Join(dir, "target"))
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
	requireNoNormalizedOutputs(t, filepath.Join(dir, "target"))
}

func TestContextDistributionsSatisfyDigestGateAndReachReceipt(t *testing.T) {
	sbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"app","version":"1.0.0"}}}`)
	sum := strings.Repeat("ab", 32)
	run := func(t *testing.T, distributions string) (run, receipt.Document) {
		t.Helper()
		dir := t.TempDir()
		manifest := "version: 1\nartifacts:\n  - id: app\n    sbom: app.json\n    context: {file: context.json}\ngate:\n  mode: fail\n  subject:\n    require: [digest]\noutput:\n  specVersionFloor: \"1.6\"\n"
		ctx := fmt.Sprintf(`{"contextVersion":1,"artifacts":[{"id":"app","sbom":{"sha256":"%s"},"source":{"repository":"https://code.example/app"}%s}]}`, index.SHA256Bytes(sbom), distributions)
		for name, data := range map[string]string{"rio.yaml": manifest, "app.json": string(sbom), "context.json": ctx} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		r := rio(t, dir, "normalize")
		paths, _ := filepath.Glob(filepath.Join(dir, "target", "rio", "runs", "*", "record.json"))
		if len(paths) != 1 {
			t.Fatalf("receipts: %v\n%s", paths, r.stderr)
		}
		d, err := receipt.Parse(readFile(t, paths[0]))
		if err != nil {
			t.Fatal(err)
		}
		return r, d
	}
	t.Run("with distributions", func(t *testing.T) {
		r, d := run(t, `,"distributions":[{"name":"app.tgz","sha256":"`+sum+`"}]`)
		requireExit(t, r, ExitOK)
		a := d.Artifacts[0]
		if a.Checks == nil || len(a.Checks.Failed) != 0 {
			t.Fatalf("checks: %+v", a.Checks)
		}
		want := []receipt.Distribution{{Name: "app.tgz", SHA256: sum, Assertion: "producer"}}
		if diff := cmp.Diff(want, a.Distributions); diff != "" {
			t.Fatalf("distributions (-want +got):\n%s", diff)
		}
	})
	t.Run("without distributions", func(t *testing.T) {
		r, d := run(t, "")
		requireExit(t, r, ExitGate)
		a := d.Artifacts[0]
		if diff := cmp.Diff([]receipt.FailedRequirement{{Requirement: "subject.digest", Count: 1}}, a.Checks.Failed); diff != "" {
			t.Fatalf("failed (-want +got):\n%s", diff)
		}
		if len(a.Distributions) != 0 {
			t.Fatalf("unexpected distributions: %v", a.Distributions)
		}
	})
}

func TestStandaloneDeliverReceiptCarriesIndexDistributions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"11111111-1111-4111-8111-111111111111"}`)
	}))
	defer srv.Close()
	dir := batchFixture(t, srv.URL)
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "synthetic")
	raw, _ := os.ReadFile("target/rio/index.json")
	idx, err := delivery.ParseIndex(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := strings.Repeat("cd", 32)
	idx.Artifacts[0].Context = &sbom.ContextRecord{Version: 1, File: buildcontext.FileRef{Path: "context.json", SHA256: sum}, Selector: "/artifacts/0", Effective: buildcontext.Artifact{ID: "app", Distributions: []buildcontext.Distribution{{Name: "app.tgz", SHA256: sum}}}, Defaulted: []string{}, Changes: []sbom.ContextChange{}, Assertion: "producer", OwnedReferences: []string{}}
	if _, err := index.Write("target/rio", &idx); err != nil {
		t.Fatal(err)
	}
	code, result, _ := runBatch(t, "deliver", "--artifact", "app", "--target", "security")
	if code != 0 {
		t.Fatal(code, result)
	}
	rawReceipt, _ := os.ReadFile(result["receipt"].(map[string]any)["path"].(string))
	d, err := receipt.Parse(rawReceipt)
	if err != nil {
		t.Fatal(err)
	}
	want := []receipt.Distribution{{Name: "app.tgz", SHA256: sum, Assertion: "producer"}}
	if len(d.Artifacts) != 1 || cmp.Diff(want, d.Artifacts[0].Distributions) != "" {
		t.Fatalf("artifacts: %+v", d.Artifacts)
	}
}
