package cli

import (
	"fmt"
	"io"
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

func TestOCIAuthModeDriftRefusesBeforeRequest(t *testing.T) {
	modes := []string{"{anonymous: true}", "{usernameEnv: COPILOT_USER, passwordEnv: COPILOT_PASSWORD}", "{bearerTokenEnv: COPILOT_TOKEN}"}
	for i, from := range modes {
		for j, to := range modes {
			if i == j {
				continue
			}
			for _, operation := range []string{"reconcile", "retry"} {
				t.Run(fmt.Sprintf("%d-to-%d-%s", i, j, operation), func(t *testing.T) {
					var calls atomic.Int32
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						io.Copy(io.Discard, r.Body)
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(500)
						io.WriteString(w, `{"errors":[{"code":"UNAVAILABLE"}]}`)
					}))
					defer server.Close()
					ip, cfg := deliveryFixture(t, "https://unused.invalid")
					config := fmt.Sprintf("version: 1\nartifacts: [{id: app, sbom: bom.json}]\ndelivery:\n  targets:\n    registry:\n      type: oci\n      registry: '%s'\n      repository: acme/app\n      allowHTTP: true\n      auth: %s\n", strings.TrimPrefix(server.URL, "http://"), from)
					os.WriteFile(cfg, []byte(config), 0600)
					c, plan, e := batchPreflight(cfg, deliveryOptions{index: ip})
					if e != nil {
						t.Fatal(e)
					}
					job := plan.Jobs[0]
					intent, e := runner.PrepareIntent(runner.Prepared{Verified: job.Verified, Description: job.Description, ExpectedReferences: job.ExpectedReferences, ValidateIntent: oci.ValidateIntent, Intent: record.Intent{RioVersion: "test", Binding: "registry", ConfigSHA256: c.SHA256}})
					if e != nil {
						t.Fatal(e)
					}
					prior := filepath.Join(t.TempDir(), "prior")
					writer, e := record.Create(prior, intent)
					if e != nil {
						t.Fatal(e)
					}
					if e = writer.Close(); e != nil {
						t.Fatal(e)
					}
					before, e := record.Read(prior)
					if e != nil {
						t.Fatal(e)
					}
					os.WriteFile(cfg, []byte(strings.Replace(config, from, to, 1)), 0600)
					for _, key := range []string{"COPILOT_USER", "COPILOT_PASSWORD", "COPILOT_TOKEN"} {
						t.Setenv(key, "synthetic-policy-secret")
					}
					args := []string{"delivery", "reconcile", "--record", prior, "--manifest", cfg}
					if operation == "retry" {
						args = []string{"deliver", "--index", ip, "--manifest", cfg, "--retry-of", prior, "--record", filepath.Join(t.TempDir(), "retry")}
					}
					code, _, _ := deliveryRun(t, args...)
					after, e := record.Read(prior)
					if code != 2 || calls.Load() != 0 || e != nil || before.SHA256 != after.SHA256 {
						t.Fatalf("auth policy drift: exit%d requests%d priorChanged=%t err=%v", code, calls.Load(), before.SHA256 != after.SHA256, e)
					}
				})
			}
		}
	}
}
