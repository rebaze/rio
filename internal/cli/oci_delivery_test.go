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
	"github.com/rebaze/rio/internal/delivery/oci"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/delivery/runner"
	"github.com/rebaze/rio/internal/receipt"
)

func TestReconcileOCIWithoutSourcesWithRotatedCredentialsAndCA(t *testing.T) {
	var requests, writes atomic.Int32
	var pub *oci.Publication
	var original []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "GET" && r.Method != "HEAD" {
			writes.Add(1)
			t.Error("read-back wrote")
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "synthetic-rotated-user" || p != "synthetic-rotated-password" {
			w.Header().Set("Www-Authenticate", `Basic realm="synthetic"`)
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/v2/" {
			w.WriteHeader(200)
			return
		}
		prefix := "/v2/acme/app/"
		path := strings.TrimPrefix(r.URL.Path, prefix)
		var raw []byte
		switch path {
		case "manifests/" + pub.Manifest.Digest, "manifests/" + pub.Tag:
			raw = []byte(pub.ManifestJSON)
			w.Header().Set("Content-Type", oci.ManifestMediaType)
			w.Header().Set("Docker-Content-Digest", pub.Manifest.Digest)
		case "blobs/" + pub.Config.Digest:
			raw = []byte("{}")
		case "blobs/sha256:" + pub.Payload.SHA256:
			raw = original
		default:
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(raw)))
		w.Write(raw)
	}))
	defer server.Close()
	ip, cfg := deliveryFixture(t, "https://unused.invalid")
	original, _ = os.ReadFile(filepath.Join(filepath.Dir(ip), "bom.json"))
	rawIndex, _ := os.ReadFile(ip)
	ca := filepath.Join(filepath.Dir(cfg), "rotated-ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	config := fmt.Sprintf("version: 1\nartifacts: [{id: app, sbom: bom.json}]\ndelivery:\n  targets:\n    registry:\n      type: oci\n      registry: '%s'\n      repository: acme/app\n      auth: {usernameEnv: OLD_USER, passwordEnv: OLD_PASSWORD}\n      caFile: /missing/historical-ca.pem\n", strings.TrimPrefix(server.URL, "https://"))
	os.WriteFile(cfg, []byte(config), 0600)
	c, plan, e := batchPreflight(cfg, deliveryOptions{index: ip})
	if e != nil {
		t.Fatal(e)
	}
	job := plan.Jobs[0]
	opts, _, e := oci.ValidateDescription(job.Description)
	if e != nil {
		t.Fatal(e)
	}
	pub = opts.Publication
	intent, e := runner.PrepareIntent(runner.Prepared{Verified: job.Verified, Description: job.Description, ExpectedReferences: job.ExpectedReferences, ValidateIntent: oci.ValidateIntent, Intent: record.Intent{RioVersion: "test", Binding: "registry", ConfigSHA256: c.SHA256}})
	if e != nil {
		t.Fatal(e)
	}
	journal := filepath.Join(t.TempDir(), "journal")
	writer, e := record.Create(journal, intent)
	if e != nil {
		t.Fatal(e)
	}
	if e = writer.Close(); e != nil {
		t.Fatal(e)
	}
	config = strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(config, "OLD_USER", "NEW_USER"), "OLD_PASSWORD", "NEW_PASSWORD"), "/missing/historical-ca.pem", filepath.ToSlash(ca))
	os.WriteFile(cfg, []byte(config), 0600)
	os.Remove(ip)
	os.Remove(filepath.Join(filepath.Dir(ip), "bom.json"))
	t.Setenv("NEW_USER", "synthetic-rotated-user")
	t.Setenv("NEW_PASSWORD", "synthetic-rotated-password")
	code, r, _ := deliveryRun(t, "delivery", "reconcile", "--record", journal, "--manifest", cfg)
	if code != 0 || r["acknowledgment"] != "unknown" || r["verification"] != "verified" || writes.Load() != 0 {
		t.Fatal(code, r)
	}
	before := requests.Load()
	for _, change := range []string{"registry", "repository", "subject", "trust", "http", "wait"} {
		t.Run(change, func(t *testing.T) {
			edited := config
			args := []string{"delivery", "reconcile", "--record", journal, "--manifest", cfg}
			switch change {
			case "registry":
				edited = strings.Replace(edited, strings.TrimPrefix(server.URL, "https://"), "unapproved.invalid", 1)
			case "repository":
				edited = strings.Replace(edited, "acme/app", "acme/other", 1)
			case "subject":
				edited += "      subject: {digest: 'sha256:" + strings.Repeat("1", 64) + "', mediaType: '" + oci.IndexMediaType + "', size: 32}\n"
			case "trust":
				edited += "      tokenServiceOrigins: [https://unapproved.invalid]\n"
			case "http":
				edited += "      allowHTTP: true\n"
			case "wait":
				args = append(args, "--wait", "1s")
			}
			os.WriteFile(cfg, []byte(edited), 0600)
			code, _, _ := deliveryRun(t, args...)
			if code != 2 || requests.Load() != before {
				t.Fatal("drift/wait sent request", change, code, requests.Load(), before)
			}
		})
	}
	os.WriteFile(cfg, []byte(config), 0600)
	os.WriteFile(ip, rawIndex, 0600)
	os.WriteFile(filepath.Join(filepath.Dir(ip), "bom.json"), original, 0600)
	prior, e := record.CaptureRead(journal, 10<<20)
	if e != nil {
		t.Fatal(e)
	}
	retry := filepath.Join(t.TempDir(), "retry")
	code, r, _ = deliveryRun(t, "deliver", "--index", ip, "--manifest", cfg, "--record", retry, "--retry-of", journal)
	if code != 0 || r["acknowledgment"] != "accepted" || r["verification"] != "verified" || writes.Load() != 0 {
		t.Fatal("already-present retry", code, r)
	}
	after, e := record.CaptureRead(journal, 10<<20)
	if e != nil || after.Snapshot.SHA256 != prior.Snapshot.SHA256 {
		t.Fatal("retry rewrote prior", e)
	}
	var stdout, stderr bytes.Buffer
	code = Main([]string{"delivery", "inspect", "--record", journal}, &stdout, &stderr)
	if code != 0 || stdout.Len() != 0 {
		t.Fatal(code, stdout.String(), stderr.String())
	}
	for _, fact := range []string{"verification: verified", "expected oci:manifest:"} {
		if !strings.Contains(stderr.String(), fact) {
			t.Errorf("missing human fact %s: %s", fact, stderr.String())
		}
	}
	testPortableOCIReceipt(t, r["receipt"].(map[string]any)["path"].(string), ip, journal, retry)

}

func testPortableOCIReceipt(t *testing.T, path, ip, journal, retry string) {
	t.Helper()
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	os.RemoveAll(filepath.Dir(ip))
	os.RemoveAll(journal)
	os.RemoveAll(retry)
	oldBuild, oldEnv := deliveryBuild, deliveryLookupEnv
	deliveryBuild = func(delivery.Provider, delivery.Description) (delivery.Target, error) {
		t.Fatal("receipt built client")
		return nil, nil
	}
	deliveryLookupEnv = func(string) (string, bool) { t.Fatal("receipt resolved credential"); return "", false }
	defer func() { deliveryBuild, deliveryLookupEnv = oldBuild, oldEnv }()
	d, e := receipt.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	if len(d.Deliveries) != 1 || d.Deliveries[0].Prior == nil {
		t.Fatal("missing current retry linkage")
	}
	content := false
	for _, o := range d.Deliveries[0].Responses {
		if o.Kind == "content" && o.Value == "verified" {
			content = true
		}
	}
	if !content {
		t.Fatal("current content observation missing")
	}
	var out, stderr bytes.Buffer
	if code := Main([]string{"record", "inspect", "--file", path, "--json"}, &out, &stderr); code != 0 {
		t.Fatal(code, stderr.String())
	}
}

func TestOCICompleteJSONExitContracts(t *testing.T) {
	for _, tc := range []struct {
		name             string
		status, exit     int
		corrupt, persist bool
	}{{"accepted", 201, 0, false, false}, {"bad-receipt", 201, 4, true, false}, {"rejected", 403, 5, false, false}, {"ambiguous", 500, 4, false, false}, {"persistence", 201, 3, false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			journal := filepath.Join(t.TempDir(), "journal")
			var puts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/" {
					w.WriteHeader(200)
					return
				}
				if r.Method == "HEAD" {
					w.WriteHeader(200)
					return
				}
				if r.Method == "GET" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(404)
					fmt.Fprint(w, `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`)
					return
				}
				if r.Method == "PUT" {
					puts.Add(1)
					raw, _ := io.ReadAll(r.Body)
					dg := "sha256:" + delivery.Digest(raw)
					if !tc.corrupt {
						w.Header().Set("Docker-Content-Digest", dg)
					}
					w.Header().Set("Location", "/v2/acme/app/manifests/"+dg)
					if tc.persist {
						os.Mkdir(filepath.Join(journal, "obstruction"), 0700)
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tc.status)
					if tc.status != 201 {
						fmt.Fprint(w, `{"errors":[{"code":"DENIED","message":"never-copy-this-synthetic-body"}]}`)
					}
					return
				}
				t.Error("unexpected upload")
			}))
			defer server.Close()
			ip, cfg := deliveryFixture(t, "https://unused.invalid")
			config := fmt.Sprintf("version: 1\nartifacts: [{id: app, sbom: bom.json}]\ndelivery:\n  targets:\n    registry:\n      type: oci\n      registry: '%s'\n      repository: acme/app\n      auth: {anonymous: true}\n      allowHTTP: true\n", strings.TrimPrefix(server.URL, "http://"))
			os.WriteFile(cfg, []byte(config), 0600)
			var stdout, stderr bytes.Buffer
			code := Main([]string{"deliver", "--out", t.TempDir(), "--index", ip, "--manifest", cfg, "--record", journal, "--json", "--quiet"}, &stdout, &stderr)
			if code != tc.exit {
				t.Fatal(code, stderr.String())
			}
			if strings.Contains(stdout.String()+stderr.String(), "never-copy-this-synthetic-body") {
				t.Fatal("body leaked")
			}
			var result runner.BatchResult
			dec := json.NewDecoder(&stdout)
			if e := dec.Decode(&result); e != nil {
				t.Fatal(e)
			}
			var extra any
			if e := dec.Decode(&extra); e != io.EOF {
				t.Fatal("extra stdout")
			}
			if result.SchemaVersion != 2 || len(result.Items) != 1 || result.Items[0].Result == nil || puts.Load() != 1 || !result.RequestMayHaveOccurred {
				t.Fatal("incomplete result")
			}
			one := result.Items[0].Result
			if one.SchemaVersion != 1 || one.Source == nil || one.Destination == nil || len(one.ExpectedReferences) != 3 || len(one.Observations) != 1 {
				t.Fatal("incomplete per-attempt result")
			}
			want := "unknown"
			if tc.exit == 0 || tc.exit == 3 {
				want = "accepted"
			}
			if tc.exit == 5 {
				want = "rejected"
			}
			if one.Acknowledgment != want || one.Persisted == tc.persist {
				t.Fatal(one.Acknowledgment, one.Persisted)
			}
		})
	}
}
func TestOCIWholeBatchIntentLimitBeforeHTTP(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(200) }))
	defer server.Close()
	ip, cfg := deliveryFixture(t, "https://unused.invalid")
	config := fmt.Sprintf("version: 1\nartifacts: [{id: app, sbom: bom.json}]\ndelivery:\n  targets:\n    first:\n      type: dependency-track\n      url: '%s'\n      allowHTTP: true\n    last:\n      type: oci\n      registry: '%s'\n      repository: acme/app\n      allowHTTP: true\n      auth: {usernameEnv: %s, passwordEnv: %s}\n", server.URL, strings.TrimPrefix(server.URL, "http://"), strings.Repeat("U", 300000), strings.Repeat("P", 300000))
	os.WriteFile(cfg, []byte(config), 0600)
	old := deliveryLookupEnv
	deliveryLookupEnv = func(string) (string, bool) { return "synthetic-value", true }
	defer func() { deliveryLookupEnv = old }()
	var stdout, stderr bytes.Buffer
	code := Main([]string{"deliver", "--out", t.TempDir(), "--index", ip, "--manifest", cfg, "--json"}, &stdout, &stderr)
	if code != 2 || requests.Load() != 0 {
		t.Fatal("HTTP before complete intent bound", code, requests.Load())
	}
	var result runner.BatchResult
	if e := json.Unmarshal(stdout.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if result.Error == nil || result.Error.Code != "size_limit" {
		t.Fatal("wrong refusal", result.Error)
	}
	if _, e := os.Stat(filepath.Join(filepath.Dir(ip), "deliveries")); !os.IsNotExist(e) {
		t.Fatal("oversized batch left journals")
	}
}
