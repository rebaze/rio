package dtrack

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
)

func tlsTarget(t *testing.T, dest string) (delivery.Description, delivery.Target) {
	t.Helper()
	d, e := (Provider{}).Describe(node(t, dest), node(t, "project: {name: app, version: '1'}"), delivery.Subject{})
	if e != nil {
		t.Fatal(e)
	}
	target, e := (Provider{}).Build(d, func(string) (string, bool) { return canary, true })
	if e != nil {
		t.Fatal(e)
	}
	return d, target
}
func tlsDetail(t *testing.T, o delivery.Observation, verification string, observed bool) {
	t.Helper()
	var got struct {
		TLS struct {
			CertificateVerification string `json:"certificateVerification"`
			Observed                bool   `json:"observed"`
		} `json:"tls"`
	}
	if json.Unmarshal(o.Details, &got) != nil || got.TLS.CertificateVerification != verification || got.TLS.Observed != observed {
		t.Fatalf("wrong TLS evidence: %s", o.Details)
	}
	b, _ := json.Marshal(o)
	if strings.Contains(string(b), canary) || strings.Contains(string(b), "certificateInvalid") {
		t.Fatal("secret or invented certificate finding")
	}
}
func TestTLSExplicitPolicyConfig(t *testing.T) {
	for _, tc := range []struct {
		extra string
		ok    bool
	}{
		{"", true}, {"\ninsecureSkipVerify: false", true}, {"\ninsecureSkipVerify: true", true},
		{"\ninsecureSkipVerify: 'true'", false}, {"\ninsecureSkipVerify: 1", false}, {"\ninsecureSkipVerify: null", false}, {"\ninsecureSkipVerify: true\ncaFile: missing.pem", false},
	} {
		t.Run(tc.extra, func(t *testing.T) {
			d, e := (Provider{}).Describe(node(t, "url: https://example.test"+tc.extra), node(t, "project: {name: app, version: '1'}"), delivery.Subject{})
			if (e == nil) != tc.ok {
				t.Fatalf("accepted=%t err=%v", e == nil, e)
			}
			if e == nil {
				if _, _, e = ValidateDescription(d); e != nil {
					t.Fatal(e)
				}
				if !strings.Contains(tc.extra, "true") && strings.Contains(string(d.Options), "insecureSkipVerify") {
					t.Fatal("default bytes changed")
				}
			}
		})
	}
	for _, dest := range []string{"url: http://example.test\nallowHTTP: true\ninsecureSkipVerify: true"} {
		if _, e := (Provider{}).Describe(node(t, dest), node(t, "project: {name: app, version: '1'}"), delivery.Subject{}); e == nil {
			t.Fatal("HTTP bypass accepted")
		}
	}
	if _, e := (Provider{}).Describe(node(t, "url: https://example.test"), node(t, "project: {name: app, version: '1'}\ninsecureSkipVerify: true"), delivery.Subject{}); e == nil {
		t.Fatal("per-artifact TLS override accepted")
	}
}
func TestTLSCertificateModesAndObservedFacts(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			io.WriteString(w, `{"token":"`+token+`"}`)
		} else {
			io.WriteString(w, `{"processing":false}`)
		}
	}))
	defer s.Close()
	ca := filepath.Join(t.TempDir(), "public-test-ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600)
	for _, tc := range []struct {
		name, extra, verify string
		ok                  bool
	}{{"default", "", "enforced", false}, {"ca", "\ncaFile: " + ca, "enforced", true}, {"bypass", "\ninsecureSkipVerify: true", "disabled", true}, {"hostname mismatch", "\ninsecureSkipVerify: true", "disabled", true}, {"verified hostname mismatch", "\ncaFile: " + ca, "enforced", false}} {
		t.Run(tc.name, func(t *testing.T) {
			url := s.URL
			if strings.Contains(tc.name, "hostname mismatch") {
				url = "https://mismatch.invalid:" + strings.Split(s.Listener.Addr().String(), ":")[1]
			}
			_, target := tlsTarget(t, "url: "+url+tc.extra)
			if strings.Contains(tc.name, "hostname mismatch") {
				tr := target.(*client).http.Transport.(*http.Transport)
				tr.Proxy = nil
				tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, s.Listener.Addr().String())
				}
			}
			before := calls.Load()
			sub, e := target.Submit(context.Background(), payload(t).Payloads())
			if (e == nil) != tc.ok || (sub.Disposition == "accepted") != tc.ok {
				t.Fatalf("%s %v", sub.Disposition, e)
			}
			tlsDetail(t, sub.Observations[0], tc.verify, tc.ok)
			if tc.ok {
				if calls.Load() != before+1 {
					t.Fatal("replayed")
				}
				o, e := target.(*client).Observe(context.Background(), sub.References)
				if e != nil {
					t.Fatal(e)
				}
				tlsDetail(t, o, tc.verify, true)
			} else if calls.Load() != before {
				t.Fatal("untrusted request sent")
			}
		})
	}
}
func TestTLSBypassDoesNotIgnoreProtocolRedirectOrLostResponse(t *testing.T) {
	for _, mode := range []string{"protocol", "redirect", "lost"} {
		t.Run(mode, func(t *testing.T) {
			var calls, redirected atomic.Int32
			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
			defer other.Close()
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				io.Copy(io.Discard, r.Body)
				if mode == "lost" {
					c, _, _ := w.(http.Hijacker).Hijack()
					c.Close()
				} else {
					http.Redirect(w, r, other.URL, 307)
				}
			}))
			if mode == "protocol" {
				s.Start()
			} else {
				s.StartTLS()
			}
			defer s.Close()
			_, target := tlsTarget(t, "url: "+strings.Replace(s.URL, "http:", "https:", 1)+"\ninsecureSkipVerify: true")
			sub, e := target.Submit(context.Background(), payload(t).Payloads())
			if e == nil || sub.Disposition != "unknown" || redirected.Load() != 0 {
				t.Fatal("ignored protocol failure or followed redirect")
			}
			want := int32(1)
			if mode == "protocol" {
				want = 0
			}
			if calls.Load() != want {
				t.Fatal("request fallback/replay")
			}
			tlsDetail(t, sub.Observations[0], "disabled", mode != "protocol")
		})
	}
}
