package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/delivery/runner"
	"gopkg.in/yaml.v3"
)

type contentProvider struct {
	builds, prepares, observes, validations int
	t                                       *testing.T
}

func (p *contentProvider) Describe(_, _ yaml.Node, _ delivery.Subject) (delivery.Description, error) {
	return delivery.Description{Type: "test-content", Identity: json.RawMessage(`{"object":"example"}`), Options: json.RawMessage(`{}`), CredentialRefs: []string{}, Capabilities: []string{"submit", "observe-content"}}, nil
}
func (p *contentProvider) Prepare(d delivery.Description, s delivery.Source, refs []delivery.PayloadRef) (delivery.Preparation, error) {
	p.prepares++
	if len(refs) != 1 || refs[0].SHA256 != s.OutputSHA256 {
		p.t.Fatal("preparation did not receive verified refs")
	}
	return delivery.Preparation{Description: d, ExpectedReferences: []delivery.Reference{{Kind: "object", Value: s.OutputSHA256}}}, nil
}
func (p *contentProvider) Build(d delivery.Description, _ func(string) (string, bool)) (delivery.Target, error) {
	p.builds++
	return p, nil
}
func (p *contentProvider) Submit(context.Context, []delivery.Payload) (delivery.Submission, error) {
	return delivery.Submission{}, nil
}
func (p *contentProvider) Observe(_ context.Context, refs []delivery.Reference) (delivery.Observation, error) {
	p.observes++
	if len(refs) != 1 || refs[0].Kind != "object" {
		p.t.Fatal("expected reference not routed", refs)
	}
	return delivery.Observation{Kind: "content", Value: "verified", Origin: "receiver", Code: "content_verified", References: refs}, nil
}
func TestAdapterContentOfflineRoutingAndIntentRecovery(t *testing.T) {
	p := &contentProvider{t: t}
	old := deliveryAdapters
	deliveryAdapters = func(dir string) map[string]adapterEntry {
		return map[string]adapterEntry{"test-content": {
			Provider: p,
			ValidateIntent: func(i record.Intent) error {
				p.validations++
				if len(i.ExpectedReferences) != 1 {
					return delivery.Fail("bad_test_intent", "expected references")
				}
				return nil
			},
			ValidateSnapshot: func(s record.Snapshot) error { p.validations++; return nil },
			SamePolicy:       func(a, b delivery.Description, _ bool) bool { return delivery.JSONEqual(a.Identity, b.Identity) },
			RecordedSubject:  func(delivery.Description) (delivery.Subject, error) { return delivery.Subject{}, nil },
			ValidateObserverReferences: func(i record.Intent, rs []delivery.Reference) error {
				if len(rs) != 1 {
					return delivery.Fail("bad_test_refs", "refs")
				}
				return nil
			},
		}}
	}
	t.Cleanup(func() { deliveryAdapters = old })
	oldEnv := deliveryLookupEnv
	deliveryLookupEnv = func(string) (string, bool) { t.Fatal("offline resolved credential"); return "", false }
	t.Cleanup(func() { deliveryLookupEnv = oldEnv })
	ip, cfg := deliveryFixture(t, "https://unused.invalid")
	b, _ := os.ReadFile(cfg)
	b = []byte(strings.Replace(string(b), "dependency-track", "test-content", 1))
	os.WriteFile(cfg, b, 0600)
	code, _, _ := deliveryRun(t, "delivery", "plan", "--manifest", cfg, "--index", ip)
	if code != 0 || p.builds != 0 || p.prepares != 1 {
		t.Fatal(code, p.builds, p.prepares)
	}
	submitted := filepath.Join(t.TempDir(), "submitted")
	code, _, _ = deliveryRun(t, "deliver", "--manifest", cfg, "--index", ip, "--record", submitted)
	if code != 4 || p.builds != 1 || p.validations == 0 {
		t.Fatal("submit policy not routed", code, p.builds, p.validations)
	}
	p.builds = 0
	c, plan, e := batchPreflight(cfg, deliveryOptions{index: ip})
	if e != nil {
		t.Fatal(e)
	}
	j := plan.Jobs[0]
	prep := runner.Prepared{Verified: j.Verified, Description: j.Description, ExpectedReferences: j.ExpectedReferences, Intent: record.Intent{RioVersion: "test", Binding: j.Target, ConfigSHA256: c.SHA256}}
	intent, e := runner.PrepareIntent(prep)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "journal")
	w, e := record.Create(path, intent)
	if e != nil {
		t.Fatal(e)
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(path, "00000000000000000000.json"))
	os.Remove(ip)
	os.Remove(filepath.Join(filepath.Dir(ip), "bom.json"))
	code, r, _ := deliveryRun(t, "delivery", "inspect", "--record", path)
	if code != 0 || r["acknowledgment"] != "unknown" || p.builds != 0 {
		t.Fatal(code, r)
	}
	code, _, _ = deliveryRun(t, "delivery", "reconcile", "--record", path, "--manifest", cfg, "--wait", "1s")
	if code != 2 || p.builds != 0 {
		t.Fatal("content wait not refused offline", code)
	}
	code, r, _ = deliveryRun(t, "delivery", "reconcile", "--record", path, "--manifest", cfg)
	if code != 0 || r["verification"] != "verified" || r["acknowledgment"] != "unknown" || p.observes != 1 || p.builds != 1 {
		t.Fatal(code, r, p.observes, p.builds)
	}
	after, _ := os.ReadFile(filepath.Join(path, "00000000000000000000.json"))
	if string(before) != string(after) {
		t.Fatal("intent changed")
	}
	w, e = record.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	sub, _ := json.Marshal(delivery.Submission{Disposition: "unknown", References: []delivery.Reference{}, Observations: []delivery.Observation{}})
	if e = w.Append("submission", sub); e == nil {
		t.Fatal("submission after recovery allowed")
	}
}
