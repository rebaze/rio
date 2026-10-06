package dtrack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/rebaze/rio/internal/delivery"
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

// Synthetic token; never real-server evidence.
const token = "f90934f5-cb88-47ce-81cb-db06fc67d4b4"
const canary = "synthetic-api-key-DO-NOT-LOG"

func payload(t testing.TB) delivery.Verified { v, _ := payloadFixture(t); return v }
func payloadFixture(t testing.TB) (delivery.Verified, string) {
	t.Helper()
	dir := t.TempDir()
	b, e := os.ReadFile("../testdata/bom.json")
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(dir, "bom.json"), b, 0600)
	h := sha256.Sum256(b)
	digest := hex.EncodeToString(h[:])
	idx := index.New("test", index.FileRef{Path: "rio.yaml", SHA256: digest})
	idx.Artifacts = []index.Artifact{{ID: "app", Input: index.FileRef{Path: "bom.json", SHA256: digest}, Output: index.FileRef{Path: "bom.json", SHA256: digest}, SpecVersion: index.SpecVersions{Input: "1.6", Output: "1.6"}, Gate: index.GateOK}}
	index.Write(dir, idx)
	v, e := delivery.Verify(filepath.Join(dir, "index.json"), "app", false)
	if e != nil {
		t.Fatal(e)
	}
	return v, filepath.Join(dir, "bom.json")
}
func targetFor(t *testing.T, s *httptest.Server, binding string, trust bool) delivery.Target {
	t.Helper()
	dest := "url: " + s.URL + "/prefix"
	if strings.HasPrefix(s.URL, "http:") {
		dest += "\nallowHTTP: true"
	}
	if trust {
		cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
		p := filepath.Join(t.TempDir(), "ca.pem")
		os.WriteFile(p, cert, 0600)
		dest += "\ncaFile: " + p
	}
	d, e := (Provider{}).Describe(node(t, dest), node(t, binding), delivery.Subject{Name: "subject", Version: "1"})
	if e != nil {
		t.Fatal(e)
	}
	target, e := (Provider{}).Build(d, func(string) (string, bool) { return canary, true })
	if e != nil {
		t.Fatal(e)
	}
	return target
}
func TestSubmitExactMultipart(t *testing.T) {
	for _, binding := range []string{"project: {name: '@literal', version: '<1'}", "project: {uuid: " + token + "}", "project: {fromSubject: true}\nautoCreate: true"} {
		t.Run(binding, func(t *testing.T) {
			v, sourcePath := payloadFixture(t)
			os.WriteFile(sourcePath, []byte(`{"replaced":true}`), 0600)
			var calls atomic.Int32
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "POST" || r.URL.Path != "/prefix/api/v1/bom" || r.Header.Get("X-Api-Key") != canary {
					t.Error("wrong request")
				}
				mr, e := r.MultipartReader()
				if e != nil {
					t.Error(e)
					return
				}
				fields := map[string]string{}
				for {
					p, e := mr.NextPart()
					if e == io.EOF {
						break
					}
					if e != nil {
						t.Error(e)
						break
					}
					b, _ := io.ReadAll(p)
					if p.FormName() == "bom" {
						if delivery.Digest(b) != v.Payloads()[0].Ref().SHA256 {
							t.Error("wrong bytes")
						}
					} else {
						fields[p.FormName()] = string(b)
					}
				}
				if strings.Contains(binding, "uuid") {
					if fields["project"] != token || len(fields) != 1 {
						t.Error(fields)
					}
				} else {
					if len(fields) != 3 || fields["projectVersion"] == "" {
						t.Error(fields)
					}
					if strings.Contains(binding, "fromSubject") {
						if fields["projectName"] != "subject" || fields["autoCreate"] != "true" {
							t.Error(fields)
						}
					} else if fields["projectName"] != "@literal" || fields["projectVersion"] != "<1" || fields["autoCreate"] != "false" {
						t.Error(fields)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"token":%q}`, token)
			}))
			defer s.Close()
			target := targetFor(t, s, binding, true)
			sub, e := target.Submit(context.Background(), v.Payloads())
			if e != nil || sub.Disposition != "accepted" || calls.Load() != 1 {
				t.Fatal(sub, e, calls.Load())
			}
		})
	}
}
func TestSubmitResponseContract(t *testing.T) {
	for _, tc := range []struct {
		name           string
		status         int
		body, ct, want string
	}{
		{"accepted", 200, `{"token":"` + token + `"}`, "application/json", "accepted"}, {"missing", 200, `{}`, "application/json", "unknown"}, {"numeric", 200, `{"token":12}`, "application/json", "unknown"}, {"created", 201, `{"token":"` + token + `"}`, "application/json", "unknown"}, {"denied", 403, `{"message":"response-secret"}`, "application/json", "rejected"}, {"proxy", 500, `{"message":"response-secret"}`, "application/json", "unknown"}, {"duplicate", 200, `{"token":"` + token + `","token":"` + token + `"}`, "application/json", "unknown"}, {"extra", 200, `{"token":"` + token + `"} {}`, "application/json", "unknown"}, {"oversize", 200, strings.Repeat("x", 65537), "application/json", "unknown"}, {"html", 200, `{"token":"` + token + `"}`, "text/html", "unknown"}, {"malformed", 200, `{`, "application/json", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", tc.ct)
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer s.Close()
			target := targetFor(t, s, "project: {name: app, version: '1'}", false)
			sub, e := target.Submit(context.Background(), payload(t).Payloads())
			if sub.Disposition != tc.want || calls.Load() != 1 {
				t.Fatal(sub, e, calls.Load())
			}
			if e != nil && (strings.Contains(e.Error(), canary) || strings.Contains(e.Error(), token) || strings.Contains(e.Error(), "response-secret")) {
				t.Fatal("secret leak")
			}
		})
	}
}
func TestSubmitLostResponseAndRedirect(t *testing.T) {
	for _, mode := range []string{"lost", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			var calls, redirected atomic.Int32
			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
			defer other.Close()
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				io.Copy(io.Discard, r.Body)
				if mode == "lost" {
					conn, _, _ := w.(http.Hijacker).Hijack()
					conn.Close()
				} else {
					http.Redirect(w, r, other.URL, 307)
				}
			}))
			defer s.Close()
			sub, _ := targetFor(t, s, "project: {name: app, version: '1'}", false).Submit(context.Background(), payload(t).Payloads())
			if sub.Disposition != "unknown" || calls.Load() != 1 || redirected.Load() != 0 {
				t.Fatal(sub, calls.Load(), redirected.Load())
			}
		})
	}
}
func TestBuildCredentialsAndTLS(t *testing.T) {
	d, e := (Provider{}).Describe(node(t, "url: https://example.test"), node(t, "project: {name: app, version: '1'}"), delivery.Subject{})
	if e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"", "bad\rkey", "bad\nkey"} {
		if _, e = (Provider{}).Build(d, func(string) (string, bool) { return key, true }); e == nil {
			t.Fatal("invalid key accepted")
		}
	}
	if _, e = (Provider{}).Build(d, func(string) (string, bool) { return "", false }); e == nil {
		t.Fatal("missing key")
	}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted server reached") }))
	defer s.Close()
	sub, e := targetFor(t, s, "project: {name: app, version: '1'}", false).Submit(context.Background(), payload(t).Payloads())
	if e == nil || sub.Disposition != "unknown" {
		t.Fatal(sub, e)
	}
}
func TestSubmitCancellationAndCardinality(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer s.Close()
	target := targetFor(t, s, "project: {name: app, version: '1'}", false)
	for _, ps := range [][]delivery.Payload{nil, {delivery.Payload{}}, {payload(t).Payloads()[0], payload(t).Payloads()[0]}} {
		if _, e := target.Submit(context.Background(), ps); e == nil {
			t.Fatal("unsupported payload")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := target.Submit(ctx, payload(t).Payloads()); e == nil {
		t.Fatal("cancel ignored")
	}
	if calls.Load() != 0 {
		t.Fatal("request on preflight refusal")
	}
}

func TestReceiptCaseVariantCannotOverrideToken(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"invalid","Token":"`+token+`"}`)
	}))
	defer s.Close()
	sub, _ := targetFor(t, s, "project: {name: app, version: '1'}", false).Submit(context.Background(), payload(t).Payloads())
	if sub.Disposition != "unknown" {
		t.Fatal("case variant fabricated receipt", sub)
	}
}
