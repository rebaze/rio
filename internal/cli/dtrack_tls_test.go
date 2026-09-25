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
	"sync/atomic"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/evidence"
)

func TestDTrackTLSSavedPolicyAndPortableEvidence(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			io.WriteString(w, `{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}`)
		} else {
			io.WriteString(w, `{"processing":false}`)
		}
	}))
	defer s.Close()
	ip, cfg := deliveryFixture(t, s.URL)
	raw, _ := os.ReadFile(cfg)
	bypass := bytes.Replace(raw, []byte("allowHTTP: true"), []byte("insecureSkipVerify: true"), 1)
	os.WriteFile(cfg, bypass, 0600)
	journal := filepath.Join(t.TempDir(), "journal")
	t.Setenv("DTRACK_API_KEY", "synthetic-tls-DO-NOT-RETAIN")
	var out, stderr bytes.Buffer
	if code := Main([]string{"delivery", "plan", "--index", ip, "--manifest", cfg}, &out, &stderr); code != 0 || !strings.Contains(stderr.String(), "insecureSkipVerify=true") {
		t.Fatalf("policy absent from offline human plan: %d %s", code, stderr.String())
	}
	if calls.Load() != 0 {
		t.Fatal("plan requested network")
	}
	code, _, _ := deliveryRun(t, "deliver", "--index", ip, "--manifest", cfg, "--record", journal)
	if code != 0 {
		t.Fatalf("bypass submission exit%d", code)
	}
	snap, e := record.Read(journal)
	if e != nil || validateSnapshot(snap) != nil {
		t.Fatal("saved TLS evidence refused", e)
	}
	code, _, _ = deliveryRun(t, "delivery", "reconcile", "--record", journal, "--manifest", cfg)
	if code != 0 {
		t.Fatalf("reconcile exit%d", code)
	}
	doc, e := evidence.Collect(ip, []string{journal}, "test", validateSnapshot, recordPolicy)
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := evidence.Marshal(doc)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(encoded, []byte("synthetic-tls-DO-NOT-RETAIN")) {
		t.Fatal("API key retained")
	}
	for _, args := range [][]string{{"delivery", "inspect", "--record", journal}, {"delivery", "reconcile", "--record", journal, "--manifest", cfg}} {
		out.Reset()
		stderr.Reset()
		if code := Main(args, &out, &stderr); code != 0 || !strings.Contains(stderr.String(), "insecureSkipVerify=true") || !strings.Contains(stderr.String(), "certificateVerification=disabled TLSObserved=true") {
			t.Fatalf("TLS absent from human evidence: %d %s", code, stderr.String())
		}
	}
	// Policy changes must reuse the same journal path and must not authorize retry/reconcile.
	os.WriteFile(cfg, raw, 0600)
	_, _, verified, _, e := singlePreflight(cfg, ip, false)
	if e != nil {
		t.Fatal(e)
	}
	if samePolicy(snap.Intent.Destination, verified, false) || samePolicy(verified, snap.Intent.Destination, true) {
		t.Fatal("verification policy drift allowed")
	}
	before := calls.Load()
	for _, args := range [][]string{{"delivery", "reconcile", "--record", journal, "--manifest", cfg}, {"deliver", "--index", ip, "--manifest", cfg, "--retry-of", journal, "--record", filepath.Join(t.TempDir(), "retry")}} {
		code, _, _ := deliveryRun(t, args...)
		if code != 2 {
			t.Fatalf("drift exit%d", code)
		}
	}
	if calls.Load() != before {
		t.Fatal("policy drift reached receiver")
	}
	if delivery.PairKey(snap.Intent.Source, snap.Intent.Destination) != delivery.PairKey(snap.Intent.Source, verified) {
		t.Fatal("flag evades same destination journal")
	}
	s.Close()
	os.RemoveAll(filepath.Dir(ip))
	os.RemoveAll(journal)
	parsed, e := evidence.Parse(encoded, validateSnapshot, recordPolicy)
	if e != nil {
		t.Fatal(e)
	}
	var human bytes.Buffer
	renderRecord(parsed, &human)
	if !strings.Contains(human.String(), "insecureSkipVerify=true") || !strings.Contains(human.String(), "certificateVerification=disabled TLSObserved=true") {
		t.Fatal("portable human record omitted TLS policy/facts")
	}
}

func TestDTrackTLSDetailsBoundToSavedPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, url, option, detail string
		ok                        bool
	}{
		{"old HTTPS", "https://unused.invalid", "", `null`, true},
		{"old HTTP", "http://unused.invalid", "", `{}`, true},
		{"verified observed", "https://unused.invalid", "", `{"tls":{"certificateVerification":"enforced","observed":true}}`, true},
		{"bypass observed", "https://unused.invalid", "insecureSkipVerify: true", `{"tls":{"certificateVerification":"disabled","observed":true}}`, true},
		{"unrecorded bypass", "https://unused.invalid", "insecureSkipVerify: true", `null`, false},
		{"wrong policy", "https://unused.invalid", "", `{"tls":{"certificateVerification":"disabled","observed":true}}`, false},
		{"wrong bypass policy", "https://unused.invalid", "insecureSkipVerify: true", `{"tls":{"certificateVerification":"enforced","observed":true}}`, false},
		{"HTTP TLS", "http://unused.invalid", "", `{"tls":{"certificateVerification":"enforced","observed":true}}`, false},
		{"receiver without TLS", "https://unused.invalid", "", `{"tls":{"certificateVerification":"enforced","observed":false}}`, false},
		{"invented validity", "https://unused.invalid", "insecureSkipVerify: true", `{"tls":{"certificateVerification":"invalid","observed":true}}`, false},
		{"secret field", "https://unused.invalid", "", `{"tls":{"certificateVerification":"enforced","observed":true,"key":"secret"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip, cfg := deliveryFixture(t, tc.url)
			if tc.option != "" {
				raw, _ := os.ReadFile(cfg)
				os.WriteFile(cfg, append(raw, []byte("      "+tc.option+"\n")...), 0600)
			}
			c, v, d, _, e := singlePreflight(cfg, ip, false)
			if e != nil {
				t.Fatal(e)
			}
			o := delivery.Observation{Kind: "activity", Value: "not-observed", Origin: "receiver", Code: "activity_observed", HTTPStatus: 200, References: []delivery.Reference{}, Details: json.RawMessage(tc.detail)}
			if tc.detail == "null" {
				o.Details = nil
			}
			snap := record.Snapshot{Intent: record.Intent{RioVersion: "test", Source: v.Source(), Payloads: []delivery.PayloadRef{v.Payloads()[0].Ref()}, Binding: "security", Destination: d, ConfigSHA256: c.SHA256}, References: []delivery.Reference{}, Observations: []delivery.Observation{o}}
			if e := validateSnapshot(snap); (e == nil) != tc.ok {
				t.Fatalf("valid=%t err=%v", e == nil, e)
			}
		})
	}
}
func TestDTrackTLSAllPairsPreflight(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer s.Close()
	for _, bad := range []string{"insecureSkipVerify: 'true'", "insecureSkipVerify: true", "insecureSkipVerify: true\n      caFile: missing.pem"} {
		ip, cfg := deliveryFixture(t, s.URL)
		raw, _ := os.ReadFile(cfg)
		raw = append(raw, []byte(fmt.Sprintf("    z-invalid:\n      type: dependency-track\n      url: %s\n      allowHTTP: true\n      %s\n", s.URL, bad))...)
		os.WriteFile(cfg, raw, 0600)
		t.Setenv("DTRACK_API_KEY", "synthetic-key")
		if code, _, _ := runBatch(t, "deliver", "--index", ip, "--manifest", cfg); code != 2 {
			t.Fatalf("invalid policy exit%d", code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("earlier selected pair wrote before TLS preflight")
	}
}
