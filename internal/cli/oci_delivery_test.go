package cli

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rebaze/rio/internal/delivery/oci"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/delivery/runner"
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
}
