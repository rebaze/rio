package cli

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/receipt"
)

func pipelineFixture(t *testing.T, target string) string {
	t.Helper()
	dir := t.TempDir()
	for _, id := range []string{"api", "worker"} {
		raw := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":%q,"version":"1.0.0"}},"components":[{"type":"library","name":"lib","version":"1","purl":"pkg:maven/org.example/lib@1"}]}`, id)
		if e := os.WriteFile(filepath.Join(dir, id+".cdx.json"), []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
	}
	man := "version: 1\nartifacts:\n  - id: api\n    sbom: api.cdx.json\n  - id: worker\n    sbom: worker.cdx.json\n"
	if target != "" {
		man += fmt.Sprintf("delivery:\n  targets:\n    security:\n      type: dependency-track\n      url: %s\n      allowHTTP: true\n", target)
	}
	if e := os.WriteFile(filepath.Join(dir, "rio.yaml"), []byte(man), 0600); e != nil {
		t.Fatal(e)
	}
	return dir
}
func rootReceipt(t *testing.T, args ...string) (int, receipt.Document, string) {
	t.Helper()
	var out, errout bytes.Buffer
	code := Main(append(args, "--json"), &out, &errout)
	if code != 0 {
		t.Logf("invocation exit=%d: %s", code, errout.String())
	}
	var result struct {
		Receipt struct {
			Path string `json:"path"`
		} `json:"receipt"`
	}
	if e := json.Unmarshal(out.Bytes(), &result); e != nil || result.Receipt.Path == "" {
		t.Fatalf("code=%d out=%s err=%s parse=%v", code, out.String(), errout.String(), e)
	}
	raw, e := os.ReadFile(result.Receipt.Path)
	if e != nil {
		t.Fatal(e)
	}
	d, e := receipt.Parse(raw)
	if e != nil {
		t.Fatalf("%v\n%s", e, raw)
	}
	return code, d, result.Receipt.Path
}
func TestPipelineOneCommandBindsSubmittedBytes(t *testing.T) {
	var payloads = map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e := r.ParseMultipartForm(1 << 20); e != nil {
			t.Error(e)
			return
		}
		defer r.MultipartForm.RemoveAll()
		f, _, e := r.FormFile("bom")
		if e != nil {
			t.Error(e)
			return
		}
		defer f.Close()
		raw, _ := io.ReadAll(f)
		payloads[r.FormValue("projectName")] = raw
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"11111111-1111-4111-8111-111111111111"}`)
	}))
	defer srv.Close()
	dir := pipelineFixture(t, srv.URL)
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "SECRET-CANARY-106")
	code, d, path := rootReceipt(t)
	if code != 0 || d.Run.Operation != "pipeline" || d.Run.Outcome != "success" || len(d.Deliveries) != 2 || len(payloads) != 2 {
		t.Fatalf("code=%d %#v uploads=%d", code, d, len(payloads))
	}
	for _, a := range d.Artifacts {
		original, _ := os.ReadFile(a.Input.Path)
		if a.Input.SHA256 != delivery.Digest(original) || a.Output.SHA256 != delivery.Digest(payloads[a.ID]) || a.Output.Size != int64(len(payloads[a.ID])) {
			t.Fatalf("binding lost: %#v", a)
		}
	}
	for _, v := range d.Deliveries {
		if v.State != "accepted" || v.Project["name"] != v.ArtifactID || v.Transport.Scheme != "http" || len(v.Responses) != 1 || v.Responses[0].HTTPStatus != 200 {
			t.Fatalf("delivery: %#v", v)
		}
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("SECRET-CANARY")) {
		t.Fatal("secret leaked")
	}
	if len(raw) > 8192 {
		t.Fatalf("receipt too large: %d", len(raw))
	}
	if _, e := os.Stat(filepath.Join(filepath.Dir(path), "index.json")); e != nil {
		t.Fatal(e)
	}
}
func TestPipelineNoTargetsAndSkipStayOffline(t *testing.T) {
	for _, skip := range []bool{false, true} {
		t.Run(fmt.Sprint(skip), func(t *testing.T) {
			target := ""
			args := []string{}
			want := "not-configured"
			if skip {
				target = "https://example.invalid"
				args = append(args, "--skip-delivery")
				want = "skipped"
			}
			dir := pipelineFixture(t, target)
			t.Chdir(dir)
			old := deliveryLookupEnv
			deliveryLookupEnv = func(string) (string, bool) { t.Fatal("offline path resolved credentials"); return "", false }
			defer func() { deliveryLookupEnv = old }()
			code, d, _ := rootReceipt(t, args...)
			if code != 0 || d.Run.Stages["delivery"] != want {
				t.Fatalf("%d %#v", code, d)
			}
		})
	}
}
func TestPipelineGatePrecedenceAndNoStaleUpload(t *testing.T) {
	for _, mode := range []string{"default", "manifest-warn", "flag-fail"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"token":"11111111-1111-4111-8111-111111111111"}`)
			}))
			defer srv.Close()
			dir := pipelineFixture(t, srv.URL)
			t.Chdir(dir)
			t.Setenv("DTRACK_API_KEY", "synthetic")
			raw, _ := os.ReadFile("api.cdx.json")
			raw = bytes.Replace(raw, []byte(`,"purl":"pkg:maven/org.example/lib@1"`), nil, 1)
			os.WriteFile("api.cdx.json", raw, 0600)
			args := []string{}
			if mode != "default" {
				f, _ := os.OpenFile("rio.yaml", os.O_APPEND|os.O_WRONLY, 0600)
				f.WriteString("gate:\n  mode: warn\n")
				f.Close()
			}
			if mode == "flag-fail" {
				args = append(args, "--gate", "fail")
			}
			code, d, _ := rootReceipt(t, args...)
			if mode == "manifest-warn" {
				if code != 0 || calls != 2 || d.Artifacts[0].Checks.Gate != "fail" || d.Artifacts[0].Checks.Mode != "warn" {
					t.Fatalf("override %d calls=%d %#v", code, calls, d)
				}
			} else if code != ExitGate || calls != 0 || d.Run.Stages["delivery"] != "not-attempted" {
				t.Fatalf("gate %d calls=%d %#v", code, calls, d)
			}
		})
	}
}
func TestPipelineExistingReceiptRefusedBeforeRequests(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer srv.Close()
	dir := pipelineFixture(t, srv.URL)
	t.Chdir(dir)
	os.WriteFile("receipt.json", []byte("prior"), 0600)
	var out, errout bytes.Buffer
	if code := Main([]string{"--receipt", "receipt.json"}, &out, &errout); code == 0 || calls != 0 {
		t.Fatalf("code=%d calls=%d", code, calls)
	}
	raw, _ := os.ReadFile("receipt.json")
	if string(raw) != "prior" {
		t.Fatal("overwritten")
	}
}
func TestPipelineOrdinaryInputFailureLeavesReceipt(t *testing.T) {
	dir := pipelineFixture(t, "")
	t.Chdir(dir)
	os.WriteFile("worker.cdx.json", []byte("broken JSON"), 0600)
	code, d, _ := rootReceipt(t)
	if code == 0 || d.Run.Outcome != "failed" || len(d.Artifacts) != 2 || d.Artifacts[1].State != "failed" || d.Run.Stages["delivery"] != "not-attempted" {
		t.Fatalf("%d %#v", code, d)
	}
}
func TestPipelineSelectionAndNewRunIsolation(t *testing.T) {
	dir := pipelineFixture(t, "")
	t.Chdir(dir)
	_, a, pa := rootReceipt(t, "--artifact", "worker")
	_, b, pb := rootReceipt(t, "--artifact", "worker")
	if pa == pb || a.Run.ID == b.Run.ID || len(a.Artifacts) != 1 || a.Artifacts[0].ID != "worker" || len(a.Exclusions) != 1 || !strings.Contains(pa, "runs") {
		t.Fatalf("%#v %#v %s %s", a, b, pa, pb)
	}
}

func TestPipelineFailureCoverageAndPartialResponse(t *testing.T) {
	for _, scenario := range []string{"gate", "credentials", "rejected", "lost-response"} {
		t.Run(scenario, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if calls.Load() == 1 {
					io.WriteString(w, `{"token":"11111111-1111-4111-8111-111111111111"}`)
					return
				}
				if scenario == "rejected" {
					w.WriteHeader(403)
					return
				}
				conn, _, e := w.(http.Hijacker).Hijack()
				if e == nil {
					conn.Close()
				}
			}))
			defer srv.Close()
			dir := pipelineFixture(t, srv.URL)
			t.Chdir(dir)
			t.Setenv("DTRACK_API_KEY", "synthetic")
			if scenario == "gate" {
				raw, _ := os.ReadFile("api.cdx.json")
				os.WriteFile("api.cdx.json", bytes.Replace(raw, []byte(`,"purl":"pkg:maven/org.example/lib@1"`), nil, 1), 0600)
			}
			if scenario == "credentials" {
				t.Setenv("DTRACK_API_KEY", "")
			}
			code, d, _ := rootReceipt(t)
			if code == 0 || len(d.Deliveries) != 2 || d.Targets["security"].URL != srv.URL {
				t.Fatalf("missing coverage: %d %#v", code, d)
			}
			if scenario == "gate" || scenario == "credentials" {
				if calls.Load() != 0 {
					t.Fatal("uploaded")
				}
				for _, v := range d.Deliveries {
					if v.State != "unattempted" || v.RequestMayHaveOccurred {
						t.Fatalf("%#v", v)
					}
				}
			} else {
				want := "unknown"
				if scenario == "rejected" {
					want = "rejected"
				}
				if calls.Load() != 2 || d.Run.Outcome != "partial" || d.Deliveries[0].State != "accepted" || d.Deliveries[1].State != want {
					t.Fatalf("calls=%d %#v", calls.Load(), d)
				}
			}
		})
	}
}

func TestPipelineContextMetadataAndVerifiedTLS(t *testing.T) {
	payloads := map[string][]byte{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e := r.ParseMultipartForm(1 << 20); e != nil {
			t.Error(e)
			return
		}
		defer r.MultipartForm.RemoveAll()
		f, _, e := r.FormFile("bom")
		if e != nil {
			t.Error(e)
			return
		}
		defer f.Close()
		payloads[r.FormValue("projectName")], _ = io.ReadAll(f)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"11111111-1111-4111-8111-111111111111"}`)
	}))
	defer srv.Close()
	dir := pipelineFixture(t, srv.URL)
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "TLS-SECRET-CANARY")
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if e := os.WriteFile("ca.pem", cert, 0600); e != nil {
		t.Fatal(e)
	}
	man, _ := os.ReadFile("rio.yaml")
	man = bytes.ReplaceAll(man, []byte("    sbom:"), []byte("    context: {file: context.json}\n    sbom:"))
	man = append(man, []byte("      caFile: ca.pem\n")...)
	os.WriteFile("rio.yaml", man, 0600)
	rows := []map[string]any{}
	for _, id := range []string{"api", "worker"} {
		raw, _ := os.ReadFile(id + ".cdx.json")
		rows = append(rows, map[string]any{"id": id, "sbom": map[string]string{"sha256": delivery.Digest(raw)}, "build": map[string]string{"url": "https://ci.example.org/runs/42", "id": "42"}})
	}
	context, _ := json.Marshal(map[string]any{"contextVersion": 1, "artifacts": rows})
	os.WriteFile("context.json", context, 0600)
	code, d, path := rootReceipt(t)
	if code != 0 {
		t.Fatal(code)
	}
	for _, a := range d.Artifacts {
		if a.Changes == nil || len(a.Changes.Metadata) != 2 {
			t.Fatalf("changes: %#v", a.Changes)
		}
		got := map[string]any{}
		for _, c := range a.Changes.Metadata {
			got[c.Field] = c.After
			if c.Before != nil || c.Assertion != "producer" {
				t.Fatalf("assertion: %#v", c)
			}
		}
		if got["build.url"] != "https://ci.example.org/runs/42" || got["build.id"] != "42" {
			t.Fatal(got)
		}
		if !bytes.Contains(payloads[a.ID], []byte("https://ci.example.org/runs/42")) || a.Output.SHA256 != delivery.Digest(payloads[a.ID]) {
			t.Fatal("submitted context missing")
		}
	}
	for _, v := range d.Deliveries {
		if v.Transport.TLSObserved == nil || !*v.Transport.TLSObserved || v.Transport.CertificateVerification != "enforced" || v.Responses[0].ObservedAt == "" || v.AttemptedAt == "" {
			t.Fatalf("TLS/time missing: %#v", v)
		}
	}
	raw, _ := os.ReadFile(path)
	if len(raw) > 8192 {
		t.Fatalf("standard TLS/context receipt %d bytes", len(raw))
	}
	if bytes.Contains(raw, []byte("TLS-SECRET-CANARY")) {
		t.Fatal("secret leak")
	}
}

func TestPipelineBrokenConsumedInputKeepsExactDigest(t *testing.T) {
	dir := pipelineFixture(t, "")
	t.Chdir(dir)
	broken := []byte("not-json\n")
	os.WriteFile("worker.cdx.json", broken, 0600)
	code, d, _ := rootReceipt(t)
	if code == 0 || d.Artifacts[1].Input == nil || d.Artifacts[1].Input.SHA256 != delivery.Digest(broken) || d.Artifacts[1].Input.Size != int64(len(broken)) || d.Artifacts[1].Output != nil {
		t.Fatalf("lost consumed identity: code=%d %#v", code, d.Artifacts[1])
	}
}
