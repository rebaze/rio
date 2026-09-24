package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/index"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func deliveryFixture(t *testing.T, url string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	b := []byte(`{"bomFormat":"CycloneDX","metadata":{"component":{"name":"app","version":"1"}}}`)
	os.WriteFile(filepath.Join(dir, "bom.json"), b, 0600)
	h := delivery.Digest(b)
	idx := index.New("test", index.FileRef{Path: "rio.yaml", SHA256: h})
	idx.Artifacts = []index.Artifact{{ID: "app", Input: index.FileRef{Path: "bom.json", SHA256: h}, Output: index.FileRef{Path: "bom.json", SHA256: h}, SpecVersion: index.SpecVersions{Input: "1.6", Output: "1.6"}, Gate: index.GateOK}}
	index.Write(dir, idx)
	cfg := filepath.Join(dir, "delivery.yaml")
	s := fmt.Sprintf("version: 1\ndestinations:\n  security:\n    type: dependency-track\n    options: {url: '%s', allowHTTP: true}\ndeliveries:\n  app-security:\n    artifact: app\n    destination: security\n    options:\n      project: {name: app, version: '1'}\n", url)
	os.WriteFile(cfg, []byte(s), 0600)
	return filepath.Join(dir, "index.json"), cfg
}
func deliveryRun(t *testing.T, args ...string) (int, map[string]any, string) {
	t.Helper()
	var out, err bytes.Buffer
	code := Main(append(args, "--json"), &out, &err)
	var result map[string]any
	d := json.NewDecoder(&out)
	if e := d.Decode(&result); e != nil {
		t.Fatalf("missing JSON code=%d stdout=%q stderr=%q", code, out.String(), err.String())
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		t.Fatal("extra stdout")
	}
	if result["schemaVersion"] != float64(1) || result["observations"] == nil {
		t.Fatal(result)
	}
	return code, result, err.String()
}
func TestDeliveryCommandRoundTrip(t *testing.T) {
	var posts, gets atomic.Int32
	var key atomic.Value
	key.Store("")
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key.Store(r.Header.Get("X-Api-Key"))
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			posts.Add(1)
			io.Copy(io.Discard, r.Body)
			io.WriteString(w, `{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}`)
		} else {
			gets.Add(1)
			io.WriteString(w, `{"processing":false}`)
		}
	}))
	defer s.Close()
	ip, cfg := deliveryFixture(t, s.URL)
	p := filepath.Join(t.TempDir(), "journal")
	t.Setenv("DTRACK_API_KEY", "synthetic-key")
	args := []string{"deliver", "--index", ip, "--config", cfg, "--delivery", "app-security", "--record", p}
	code, r, _ := deliveryRun(t, args...)
	if code != 0 || r["outcome"] != "accepted" || posts.Load() != 1 {
		t.Fatal(code, r)
	}
	code, r, _ = deliveryRun(t, "delivery", "inspect", "--record", p)
	if code != 0 || r["outcome"] != "accepted" {
		t.Fatal(code, r)
	}
	// Reconciliation must use recorded subject/identity and needs no original index/SBOM.
	os.Remove(ip)
	os.Remove(filepath.Join(filepath.Dir(ip), "bom.json"))
	b, _ := os.ReadFile(cfg)
	b = bytes.Replace(b, []byte("allowHTTP: true"), []byte("allowHTTP: true, apiKeyEnv: ROTATED_KEY"), 1)
	os.WriteFile(cfg, b, 0600)
	t.Setenv("ROTATED_KEY", "rotated-synthetic-key")
	code, r, _ = deliveryRun(t, "delivery", "reconcile", "--record", p, "--config", cfg)
	if code != 0 || r["activity"] != "not-observed" || r["acknowledgment"] != "accepted" || key.Load() != "rotated-synthetic-key" || gets.Load() != 1 || posts.Load() != 1 {
		t.Fatal(code, r, key.Load())
	}
	b = bytes.Replace(b, []byte(s.URL), []byte("http://127.0.0.1:1"), 1)
	os.WriteFile(cfg, b, 0600)
	code, _, _ = deliveryRun(t, "delivery", "reconcile", "--record", p, "--config", cfg)
	if code != 2 || gets.Load() != 1 {
		t.Fatal("drift not refused", code)
	}
}
func TestDeliveryOfflineAndPreflight(t *testing.T) {
	ip, cfg := deliveryFixture(t, "http://127.0.0.1:1")
	t.Setenv("DTRACK_API_KEY", "bad\nkey")
	p := filepath.Join(t.TempDir(), "journal")
	code, r, _ := deliveryRun(t, "delivery", "plan", "--index", ip, "--config", cfg, "--delivery", "app-security", "--quiet")
	if code != 0 || r["outcome"] != "ready" {
		t.Fatal(code, r)
	}
	code, _, _ = deliveryRun(t, "deliver", "--index", ip, "--config", cfg, "--delivery", "app-security", "--record", p)
	if code != 2 {
		t.Fatal(code)
	}
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("journal created on credential failure")
	}
	for _, flag := range []string{"--manifest", "--out"} {
		code, _, _ = deliveryRun(t, "delivery", "plan", "--index", ip, "--config", cfg, "--delivery", "app-security", flag, "ignored")
		if code != 2 {
			t.Fatal("inherited flag ignored")
		}
	}
}
func TestDeliveryRetry(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}`)
	}))
	defer s.Close()
	ip, cfg := deliveryFixture(t, s.URL)
	t.Setenv("DTRACK_API_KEY", "synthetic-key")
	dir := t.TempDir()
	prior := filepath.Join(dir, "prior")
	args := []string{"deliver", "--index", ip, "--config", cfg, "--delivery", "app-security"}
	if code, _, _ := deliveryRun(t, append(args, "--record", prior)...); code != 0 {
		t.Fatal(code)
	}
	// Orphan temps are not committed evidence; explicit retry still authorizes a possible duplicate.
	if e := os.WriteFile(filepath.Join(prior, ".event-orphan.tmp"), []byte("partial result"), 0600); e != nil {
		t.Fatal(e)
	}
	before, e := record.Read(prior)
	if e != nil {
		t.Fatal(e)
	}
	next := filepath.Join(dir, "retry")
	if code, result, errout := deliveryRun(t, append(args, "--retry-of", prior, "--record", next)...); code != 0 {
		t.Fatal(code, result, errout)
	}
	after, _ := record.Read(prior)
	retry, _ := record.Read(next)
	if before.SHA256 != after.SHA256 || retry.Intent.Retry.AttemptID != before.Events[0].AttemptID || retry.Events[0].AttemptID == before.Events[0].AttemptID {
		t.Fatal("bad retry linkage")
	}
	b, _ := os.ReadFile(ip)
	os.WriteFile(ip, append(b, ' '), 0600)
	code, _, _ := deliveryRun(t, append(args, "--retry-of", prior, "--record", filepath.Join(dir, "refused"))...)
	if code != 2 || calls.Load() != 2 {
		t.Fatal("changed index retried")
	}
}
func TestDeliveryExitCodes(t *testing.T) {
	for _, tc := range []struct {
		status, exit int
		body         string
	}{{200, 0, `{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}`}, {403, 5, `{"secret":"never-print"}`}, {200, 4, `{}`}, {500, 4, `{"secret":"never-print"}`}} {
		t.Run(fmt.Sprint(tc.status, tc.exit), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer s.Close()
			ip, cfg := deliveryFixture(t, s.URL)
			t.Setenv("DTRACK_API_KEY", "canary-never-print")
			p := filepath.Join(t.TempDir(), "journal")
			code, r, errout := deliveryRun(t, "deliver", "--index", ip, "--config", cfg, "--delivery", "app-security", "--record", p)
			b, _ := json.Marshal(r)
			if code != tc.exit || strings.Contains(string(b)+errout, "never-print") {
				t.Fatal(code, r, errout)
			}
			if tc.exit == 4 {
				code, _, _ = deliveryRun(t, "delivery", "reconcile", "--record", p, "--config", cfg)
				if code != 2 {
					t.Fatal("missing token not refused")
				}
			}
		})
	}
}

func TestDeliveryOfflineNeverBuildsClient(t *testing.T) {
	oldBuild, oldLookup := deliveryBuild, deliveryLookupEnv
	defer func() { deliveryBuild = oldBuild; deliveryLookupEnv = oldLookup }()
	builds, secrets := 0, 0
	deliveryBuild = func(p delivery.Provider, d delivery.Description) (delivery.Target, error) {
		builds++
		return oldBuild(p, d)
	}
	deliveryLookupEnv = func(s string) (string, bool) { secrets++; return oldLookup(s) }
	ip, cfg := deliveryFixture(t, "https://unreachable.invalid")
	t.Setenv("DTRACK_API_KEY", "invalid\nkey")
	code, _, _ := deliveryRun(t, "delivery", "plan", "--index", ip, "--config", cfg, "--delivery", "app-security")
	if code != 0 {
		t.Fatal(code)
	}
	var out, err bytes.Buffer
	for _, args := range [][]string{{"--help"}, {"version"}, {"plan", "--manifest", filepath.Join(filepath.Dir(ip), "rio.yaml")}, {"normalize", "--manifest", filepath.Join(filepath.Dir(ip), "rio.yaml")}} {
		Main(args, &out, &err)
	}
	p := filepath.Join(t.TempDir(), "journal")
	c, v, d, _, e := preflight(deliveryOptions{index: ip, config: cfg, binding: "app-security"})
	if e != nil {
		t.Fatal(e)
	}
	w, e := record.Create(p, record.Intent{RioVersion: "test", Source: v.Source(), Payloads: []delivery.PayloadRef{v.Payloads()[0].Ref()}, Binding: "app-security", Destination: d, ConfigSHA256: c.SHA256})
	if e != nil {
		t.Fatal(e)
	}
	w.Close()
	code, r, _ := deliveryRun(t, "delivery", "inspect", "--record", p)
	if code != 0 || r["outcome"] != "unknown" {
		t.Fatal(code, r)
	}
	if builds != 0 || secrets != 0 {
		t.Fatal("offline command constructed client", builds, secrets)
	}
}

func TestNormalizeAndPlanIgnoreDeliveryCredentials(t *testing.T) {
	manifest, err := filepath.Abs("../../tools/demo-repair/rio.yaml")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DTRACK_API_KEY", "invalid\ncredential")
	for _, op := range []string{"normalize", "plan"} {
		var out, stderr bytes.Buffer
		args := []string{op, "--manifest", manifest, "--out", t.TempDir()}
		if op == "plan" {
			args = append(args, "--json")
		}
		if code := Main(args, &out, &stderr); code != 0 {
			t.Fatal(op, code, stderr.String())
		}
	}
}

func TestDeliveryPersistenceFailureReportsAcceptance(t *testing.T) {
	p := filepath.Join(t.TempDir(), "journal")
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		io.Copy(io.Discard, r.Body)
		os.Mkdir(filepath.Join(p, "unexpected"), 0700)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}`)
	}))
	defer s.Close()
	ip, cfg := deliveryFixture(t, s.URL)
	t.Setenv("DTRACK_API_KEY", "synthetic-key")
	code, r, _ := deliveryRun(t, "deliver", "--index", ip, "--config", cfg, "--delivery", "app-security", "--record", p)
	if code != 3 || r["outcome"] != "accepted" || r["persisted"] != false || r["requestMayHaveOccurred"] != true || calls != 1 {
		t.Fatal(code, r, calls)
	}
}

func TestHumanDeliveryPlanShowsVerifiedFacts(t *testing.T) {
	ip, cfg := deliveryFixture(t, "https://example.test")
	var out, stderr bytes.Buffer
	code := Main([]string{"delivery", "plan", "--index", ip, "--config", cfg, "--delivery", "app-security"}, &out, &stderr)
	text := out.String() + stderr.String()
	if code != 0 {
		t.Fatal(code, text)
	}
	for _, fact := range []string{"https://example.test", "schemaValidated=false", "gate=ok", "sha256=", "submit", "observe-activity"} {
		if !strings.Contains(text, fact) {
			t.Errorf("human output missing %s: %s", fact, text)
		}
	}
}

func TestPreflightUsesOneConfigurationSnapshot(t *testing.T) {
	ip, cfg := deliveryFixture(t, "https://original.example")
	c, e := delivery.LoadConfig(cfg)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(cfg)
	b = bytes.ReplaceAll(b, []byte("original.example"), []byte("replacement.example"))
	b = bytes.ReplaceAll(b, []byte("artifact: app"), []byte("artifact: other"))
	os.WriteFile(cfg, b, 0600)
	_, v, d, _, e := preflightLoaded(c, deliveryOptions{index: ip, config: cfg, binding: "app-security"})
	if e != nil {
		t.Fatal(e)
	}
	if v.Source().ArtifactID != "app" || !strings.Contains(string(d.Identity), "original.example") {
		t.Fatal("mixed config snapshots", v.Source(), string(d.Identity))
	}
}

func TestHumanInspectSeparatesEvidenceAndReportsTemps(t *testing.T) {
	ip, cfg := deliveryFixture(t, "https://example.test")
	c, v, d, _, e := preflight(deliveryOptions{index: ip, config: cfg, binding: "app-security", allowFailed: true})
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(t.TempDir(), "record")
	w, e := record.Create(p, record.Intent{RioVersion: "test", Source: v.Source(), Payloads: []delivery.PayloadRef{v.Payloads()[0].Ref()}, Binding: "app-security", Destination: d, ConfigSHA256: c.SHA256})
	if e != nil {
		t.Fatal(e)
	}
	refs := []delivery.Reference{{Kind: "dependency-track:event-token", Value: "f90934f5-cb88-47ce-81cb-db06fc67d4b4"}}
	sub := delivery.Submission{Disposition: "accepted", References: refs, Observations: []delivery.Observation{{Kind: "acknowledgment", Value: "accepted", Origin: "receiver", Code: "accepted", HTTPStatus: 200, References: refs}}}
	b, _ := json.Marshal(sub)
	if e = w.Append("submission", b); e != nil {
		t.Fatal(e)
	}
	b, _ = json.Marshal(record.Reconciliation{ConfigSHA256: c.SHA256, Observation: delivery.Observation{Kind: "activity", Value: "not-observed", Origin: "receiver", Code: "activity_observed", HTTPStatus: 200, References: []delivery.Reference{}}})
	if e = w.Append("reconciliation", b); e != nil {
		t.Fatal(e)
	}
	w.Close()
	os.WriteFile(filepath.Join(p, ".event-orphan.tmp"), []byte("uncommitted"), 0600)
	var out, stderr bytes.Buffer
	code := Main([]string{"delivery", "inspect", "--record", p}, &out, &stderr)
	text := out.String() + stderr.String()
	if code != 0 {
		t.Fatal(code, text)
	}
	for _, fact := range []string{"acknowledgment: accepted", "activity: no processing observed", "schemaValidated=false", "allowFailedGate=true", "orphan temporary files ignored: 1"} {
		if !strings.Contains(text, fact) {
			t.Errorf("missing %s: %s", fact, text)
		}
	}
}

func TestReconcileReportsCleanupFailureBeforeJSON(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Error("unexpected reconciliation request")
		}
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}`)
	}))
	defer s.Close()
	ip, cfg := deliveryFixture(t, s.URL)
	p := filepath.Join(t.TempDir(), "record")
	t.Setenv("DTRACK_API_KEY", "synthetic-key")
	if code, _, _ := deliveryRun(t, "deliver", "--index", ip, "--config", cfg, "--delivery", "app-security", "--record", p); code != 0 {
		t.Fatal(code)
	}
	old := deliveryBuild
	defer func() { deliveryBuild = old }()
	deliveryBuild = func(delivery.Provider, delivery.Description) (delivery.Target, error) {
		if e := os.WriteFile(filepath.Join(p+".lock", "obstruction"), []byte("x"), 0600); e != nil {
			t.Fatal(e)
		}
		return nil, delivery.Fail("invalid_credential", "injected preflight failure")
	}
	code, r, _ := deliveryRun(t, "delivery", "reconcile", "--record", p, "--config", cfg)
	if code != 3 || r["requestMayHaveOccurred"] != false || r["error"].(map[string]any)["code"] != "persistence_failed" {
		t.Fatal(code, r)
	}
}

func TestMalformedSubjectRequiresOnlySubjectSelectorToRefuse(t *testing.T) {
	for _, selector := range []string{"{name: app, version: '1'}", "{uuid: f90934f5-cb88-47ce-81cb-db06fc67d4b4}", "{fromSubject: true}"} {
		t.Run(selector, func(t *testing.T) {
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}`)
			}))
			defer s.Close()
			ip, cfg := deliveryFixture(t, s.URL)
			payload := []byte(`{"bomFormat":"CycloneDX","metadata":{"component":{"name":12,"version":"1"}}}`)
			os.WriteFile(filepath.Join(filepath.Dir(ip), "bom.json"), payload, 0600)
			b, _ := os.ReadFile(ip)
			var idx map[string]any
			json.Unmarshal(b, &idx)
			a := idx["artifacts"].([]any)[0].(map[string]any)
			a["output"].(map[string]any)["sha256"] = delivery.Digest(payload)
			a["gate"] = "fail"
			b, _ = json.Marshal(idx)
			os.WriteFile(ip, b, 0600)
			b, _ = os.ReadFile(cfg)
			b = bytes.Replace(b, []byte("{name: app, version: '1'}"), []byte(selector), 1)
			os.WriteFile(cfg, b, 0600)
			t.Setenv("DTRACK_API_KEY", "synthetic-key")
			code, r, _ := deliveryRun(t, "deliver", "--index", ip, "--config", cfg, "--delivery", "app-security", "--record", filepath.Join(t.TempDir(), "record"), "--allow-failed-gate")
			if strings.Contains(selector, "fromSubject") {
				if code != 2 || calls != 0 || r["error"].(map[string]any)["code"] != "invalid_subject" {
					t.Fatal(code, r, calls)
				}
			} else if code != 0 || calls != 1 {
				t.Fatal(code, r, calls)
			}
		})
	}
}
