package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
)

func TestManifestOutputAndGatePrecedenceMatchPlan(t *testing.T) {
	dir := pipelineFixture(t, "")
	t.Chdir(dir)
	cwd, _ := os.Getwd()
	f, _ := os.OpenFile("rio.yaml", os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString("output:\n  directory: from-manifest\ngate:\n  mode: warn\n")
	f.Close()
	for _, override := range []bool{false, true} {
		t.Run(map[bool]string{false: "manifest", true: "flags"}[override], func(t *testing.T) {
			args := []string{"plan", "--json"}
			wantOut := filepath.Join(cwd, "from-manifest")
			wantGate := "warn"
			if override {
				args = append(args, "--out", "explicit", "--gate", "fail")
				wantOut = "explicit"
				wantGate = "fail"
			}
			var out, stderr bytes.Buffer
			if code := Main(args, &out, &stderr); code != 0 {
				t.Fatalf("plan code=%d %s", code, stderr.String())
			}
			var p map[string]any
			if e := json.Unmarshal(out.Bytes(), &p); e != nil {
				t.Fatal(e)
			}
			if p["out"] != filepath.ToSlash(wantOut) || p["gate"].(map[string]any)["mode"] != wantGate || !strings.Contains(p["runDirectory"].(string), "runs/<run-id>") {
				t.Fatal(p)
			}
			if _, e := os.Stat(wantOut); !os.IsNotExist(e) {
				t.Fatal("plan created output")
			}
			runArgs := []string{}
			if override {
				runArgs = []string{"--out", "explicit", "--gate", "fail"}
			}
			code, d, path := rootReceipt(t, runArgs...)
			if code != 0 || d.Artifacts[0].Checks.Mode != wantGate {
				t.Fatalf("run %d %#v", code, d)
			}
			absolute, _ := filepath.Abs(wantOut)
			absolute, _ = filepath.EvalSymlinks(absolute)
			if !strings.HasPrefix(filepath.Dir(path), absolute+string(filepath.Separator)) {
				t.Fatalf("plan/run output disagree %s vs %s", path, absolute)
			}
			if override && d.Run.Overrides["out"] != "explicit" {
				t.Fatal("output override absent", d.Run.Overrides)
			}
		})
	}
}
func TestPipelinePlanRoutesWithoutReadingInputsOrBuildingClients(t *testing.T) {
	dir := pipelineFixture(t, "https://receiver.example.org")
	t.Chdir(dir)
	raw, _ := os.ReadFile("rio.yaml")
	raw = bytes.ReplaceAll(raw, []byte("    sbom:"), []byte("    transforms: [{repair-purl: {ecosystem: p2, table: absent.json}}]\n    sbom:"))
	raw = append(raw, []byte("    excluded:\n      type: dependency-track\n      url: https://excluded.example.org\n      exclude: [worker]\n")...)
	os.WriteFile("rio.yaml", raw, 0600)
	os.WriteFile("worker.cdx.json", []byte("plan does not read SBOM bytes"), 0600)
	oldBuild, oldEnv := deliveryBuild, deliveryLookupEnv
	deliveryBuild = func(delivery.Provider, delivery.Description) (delivery.Target, error) {
		t.Fatal("plan built client")
		return nil, nil
	}
	deliveryLookupEnv = func(string) (string, bool) { t.Fatal("plan resolved credentials"); return "", false }
	defer func() { deliveryBuild, deliveryLookupEnv = oldBuild, oldEnv }()
	var out, stderr bytes.Buffer
	if code := Main([]string{"plan", "--json", "--artifact", "worker", "--target", "security", "--skip-delivery"}, &out, &stderr); code != 0 {
		t.Fatalf("%d %s", code, stderr.String())
	}
	var p map[string]any
	json.Unmarshal(out.Bytes(), &p)
	if len(p["artifacts"].([]any)) != 1 {
		t.Fatal(p)
	}
	routing := p["delivery"].(map[string]any)
	if routing["mode"] != "skipped" || len(routing["targets"].(map[string]any)) != 2 || len(routing["pairs"].([]any)) != 1 || len(p["exclusions"].([]any)) != 2 {
		t.Fatal(p)
	}
	pair := routing["pairs"].([]any)[0].(map[string]any)
	if pair["artifactId"] != "worker" || pair["projectSource"] != "normalized-subject" {
		t.Fatal(pair)
	}
	if _, e := os.Stat("target"); !os.IsNotExist(e) {
		t.Fatal("plan wrote")
	}
}
func TestFailedInputRetainsConfiguredDestinationCoverage(t *testing.T) {
	dir := pipelineFixture(t, "https://receiver.example.org")
	t.Chdir(dir)
	os.WriteFile("worker.cdx.json", []byte("broken"), 0600)
	code, d, _ := rootReceipt(t)
	if code == 0 || len(d.Targets) != 1 || len(d.Deliveries) != 2 {
		t.Fatalf("coverage lost %d %#v", code, d)
	}
	for _, v := range d.Deliveries {
		if v.State != "unattempted" || v.RequestMayHaveOccurred {
			t.Fatal(v)
		}
	}
}

func TestArtifactFilterDoesNotResolveExcludedSBOMs(t *testing.T) {
	dir := pipelineFixture(t, "")
	t.Chdir(dir)
	os.Remove("api.cdx.json")
	for _, args := range [][]string{{"plan", "--json", "--artifact", "worker"}, {"--json", "--artifact", "worker"}} {
		var out, stderr bytes.Buffer
		if code := Main(args, &out, &stderr); code != 0 {
			t.Fatalf("excluded missing input blocked selected work: %v code=%d %s", args, code, stderr.String())
		}
	}
}
func TestStandaloneDeliveryUsesManifestOutputRoot(t *testing.T) {
	dir := batchFixture(t, "https://receiver.example.org")
	t.Chdir(t.TempDir())
	t.Setenv("DTRACK_API_KEY", "")
	f, _ := os.OpenFile(filepath.Join(dir, "rio.yaml"), os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString("output:\n  directory: receipts\n")
	f.Close()
	var out, stderr bytes.Buffer
	code := Main([]string{"deliver", "--manifest", filepath.Join(dir, "rio.yaml"), "--index", filepath.Join(dir, "target", "rio", "index.json"), "--json"}, &out, &stderr)
	var result struct {
		RunDirectory string `json:"runDirectory"`
	}
	json.Unmarshal(out.Bytes(), &result)
	expected, _ := filepath.EvalSymlinks(dir)
	actual, _ := filepath.EvalSymlinks(result.RunDirectory)
	if code != ExitUsage || !strings.HasPrefix(actual, filepath.Join(expected, "receipts", "runs")+string(filepath.Separator)) {
		t.Fatalf("manifest output ignored code=%d out=%s err=%s", code, out.String(), stderr.String())
	}
}

func TestPlanPairOrderMatchesExecution(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"11111111-1111-4111-8111-111111111111"}`)
	}))
	defer srv.Close()
	dir := pipelineFixture(t, srv.URL+"/security")
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "synthetic")
	f, _ := os.OpenFile("rio.yaml", os.O_APPEND|os.O_WRONLY, 0600)
	fmt.Fprintf(f, "    archive:\n      type: dependency-track\n      url: %s/archive\n      allowHTTP: true\n", srv.URL)
	f.Close()
	var out, stderr bytes.Buffer
	if code := Main([]string{"plan", "--json"}, &out, &stderr); code != 0 {
		t.Fatal(code, stderr.String())
	}
	var p struct {
		Delivery planRouting `json:"delivery"`
	}
	json.Unmarshal(out.Bytes(), &p)
	code, d, _ := rootReceipt(t)
	if code != 0 {
		t.Fatal(code)
	}
	for i, pair := range p.Delivery.Pairs {
		if pair.ArtifactID != d.Deliveries[i].ArtifactID || pair.Target != d.Deliveries[i].Target {
			t.Fatalf("plan/execution order diverged at %d: %#v %#v", i, pair, d.Deliveries[i])
		}
	}
}

func TestMissingInputRetainsPlannedScopeAndAccuratePhase(t *testing.T) {
	dir := pipelineFixture(t, "https://receiver.example.org")
	t.Chdir(dir)
	os.Remove("api.cdx.json")
	code, d, _ := rootReceipt(t)
	if code != ExitUsage || len(d.Artifacts) != 2 || len(d.Deliveries) != 2 || len(d.Targets) != 1 || d.Run.Stages["intake"] != "failed" || d.Run.Stages["normalize"] != "not-attempted" {
		t.Fatalf("lost scope/phases: %d %#v", code, d)
	}
}
func TestConsumedInvalidInputDoesNotClaimNormalizationWasAttempted(t *testing.T) {
	dir := pipelineFixture(t, "")
	t.Chdir(dir)
	os.WriteFile("api.cdx.json", []byte("bad"), 0600)
	code, d, _ := rootReceipt(t)
	if code != ExitUsage || d.Run.Stages["intake"] != "failed" || d.Run.Stages["normalize"] != "not-attempted" || d.Artifacts[0].Input == nil {
		t.Fatalf("incorrect phases %d %#v", code, d)
	}
}
