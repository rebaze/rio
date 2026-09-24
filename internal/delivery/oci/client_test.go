package oci

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rebaze/rio/internal/delivery"
)

const secretCanary = "synthetic-secret-never-record-this"

func clientDescription(t testing.TB, endpoint, authConfig, extra string) delivery.Description {
	t.Helper()
	plain := strings.HasPrefix(endpoint, "http:")
	d, e := (Provider{}).Describe(node(t, "registry: '"+strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")+"'\nrepository: acme/app\nauth: "+authConfig+"\nallowHTTP: "+map[bool]string{true: "true", false: "false"}[plain]+"\n"+extra), node(t, "{}"), delivery.Subject{})
	if e != nil {
		t.Fatal(e)
	}
	s, ref := sourceRef()
	p, e := (Provider{}).Prepare(d, s, []delivery.PayloadRef{ref})
	if e != nil {
		t.Fatal(e)
	}
	return p.Description
}
func buildClient(t testing.TB, d delivery.Description) *client {
	t.Helper()
	target, e := (Provider{}).Build(d, func(string) (string, bool) { return secretCanary, true })
	if e != nil {
		t.Fatal(e)
	}
	return target.(*client)
}
func TestClientPreflightSecrets(t *testing.T) {
	d := clientDescription(t, "https://registry.example", "{usernameEnv: USER, passwordEnv: PASSWORD}", "")
	for _, v := range []string{"", "\rsecret", "secret\n", "secret\x00", "secret\t", "secret\x7f", "secret\u0085"} {
		_, e := (Provider{}).Build(d, func(string) (string, bool) { return v, true })
		if e == nil || strings.Contains(e.Error(), "secret") {
			t.Fatal("credential was accepted/leaked", e)
		}
	}
	if _, e := (Provider{}).Build(d, func(string) (string, bool) { return "", false }); e == nil {
		t.Fatal("absent secret")
	}
	calls := 0
	d = clientDescription(t, "https://registry.example", "{anonymous: true}", "")
	if _, e := (Provider{}).Build(d, func(string) (string, bool) { calls++; return "", false }); e != nil || calls != 0 {
		t.Fatal(e, calls)
	}
}
func TestClientTLS(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer s.Close()
	for _, trusted := range []bool{false, true} {
		extra := ""
		if trusted {
			pool := x509.NewCertPool()
			pool.AddCert(s.Certificate())
			path := filepath.Join(t.TempDir(), "ca.pem")
			os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600)
			extra = "caFile: '" + filepath.ToSlash(path) + "'\n"
		}
		c := buildClient(t, clientDescription(t, s.URL, "{anonymous: true}", extra))
		ctx, cancel := c.traversal(context.Background(), false)
		r, e := c.request(ctx, "GET", "/v2/", nil, 0, "")
		cancel()
		if r != nil {
			r.Body.Close()
		}
		if (e == nil) != trusted {
			t.Fatal("TLS trust", trusted, e)
		}
	}
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
}
func TestAuthBasicAndBounded401(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		u, p, ok := r.BasicAuth()
		if !ok || u != secretCanary || p != secretCanary {
			w.Header().Set("Www-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	defer s.Close()
	c := buildClient(t, clientDescription(t, s.URL, "{usernameEnv: USER, passwordEnv: PASSWORD}", ""))
	ctx, cancel := c.traversal(context.Background(), true)
	defer cancel()
	r, e := c.request(ctx, "GET", "/v2/", nil, 0, "")
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if calls.Load() != 2 {
		t.Fatal("auth negotiation", calls.Load())
	}
	r, e = c.request(ctx, "GET", "/v2/", nil, 0, "")
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if calls.Load() != 3 {
		t.Fatal("auth not cached", calls.Load())
	}
}
func TestAuthBearerTrustAndScope(t *testing.T) {
	for _, scope := range []string{"repository:acme/app:pull,push", "repository:other/app:pull,push", "registry:catalog:*"} {
		t.Run(scope, func(t *testing.T) {
			var tokenCalls atomic.Int32
			var s *httptest.Server
			s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" {
					tokenCalls.Add(1)
					if r.URL.Query().Get("scope") != "repository:acme/app:pull,push" {
						t.Error("scope widened")
					}
					u, p, ok := r.BasicAuth()
					if !ok || u != secretCanary || p != secretCanary {
						t.Error("auth absent")
					}
					w.Header().Set("Content-Type", "application/json")
					io.WriteString(w, `{"token":"synthetic-token"}`)
					return
				}
				if r.Header.Get("Authorization") == "Bearer synthetic-token" {
					w.WriteHeader(200)
					return
				}
				w.Header().Set("Www-Authenticate", `Bearer realm="`+s.URL+`/token",service="synthetic",scope="`+scope+`"`)
				w.WriteHeader(401)
			}))
			defer s.Close()
			c := buildClient(t, clientDescription(t, s.URL, "{usernameEnv: USER, passwordEnv: PASSWORD}", ""))
			ctx, cancel := c.traversal(context.Background(), true)
			defer cancel()
			r, e := c.request(ctx, "GET", "/v2/", nil, 0, "")
			if r != nil {
				r.Body.Close()
			}
			want := scope == "repository:acme/app:pull,push"
			if (e == nil) != want || tokenCalls.Load() != map[bool]int32{true: 1, false: 0}[want] {
				t.Fatal(e, tokenCalls.Load())
			}
		})
	}
}
func TestAuthUnapprovedRealmAndRedirect(t *testing.T) {
	for _, mode := range []string{"realm", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			var leaked atomic.Int32
			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
			defer other.Close()
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "realm" {
					w.Header().Set("Www-Authenticate", `Bearer realm="`+other.URL+`/token"`)
					w.WriteHeader(401)
				} else {
					w.Header().Set("Location", other.URL+"/signed?secret="+secretCanary)
					w.WriteHeader(307)
				}
			}))
			defer s.Close()
			c := buildClient(t, clientDescription(t, s.URL, "{usernameEnv: USER, passwordEnv: PASSWORD}", ""))
			ctx, cancel := c.traversal(context.Background(), true)
			defer cancel()
			r, e := c.request(ctx, "GET", "/v2/", nil, 0, "")
			if r != nil {
				r.Body.Close()
			}
			if mode == "realm" && e == nil {
				t.Fatal("realm accepted")
			}
			if e != nil && strings.Contains(e.Error(), secretCanary) {
				t.Fatal("error leaked")
			}
			if leaked.Load() != 0 {
				t.Fatal("credentials/request escaped")
			}
		})
	}
}
func TestClientNoWriteReplay(t *testing.T) {
	for _, status := range []int{429, 500, 307, 0, 401} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, _ := io.ReadAll(r.Body)
				if string(body) != "snapshot" {
					t.Error("body lost")
				}
				if status == 0 {
					conn, _, _ := w.(http.Hijacker).Hijack()
					conn.Close()
					return
				}
				if status == 401 {
					w.Header().Set("Www-Authenticate", `Basic realm="synthetic"`)
				}
				w.WriteHeader(status)
			}))
			defer s.Close()
			c := buildClient(t, clientDescription(t, s.URL, "{usernameEnv: USER, passwordEnv: PASSWORD}", ""))
			ctx, cancel := c.traversal(context.Background(), true)
			defer cancel()
			r, e := c.request(ctx, "PUT", "/v2/acme/app/manifests/test", func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("snapshot")), nil }, 8, ManifestMediaType)
			if r != nil {
				r.Body.Close()
			}
			if e != nil && strings.Contains(e.Error(), s.URL) {
				t.Fatal("unsafe error", e)
			}
			want := int32(1)
			if status == 401 {
				want = 2
			}
			if calls.Load() != want {
				t.Fatal("write replay count", calls.Load())
			}
		})
	}
}
func TestClientBoundsAndCancellation(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "4194305")
		w.WriteHeader(200)
	}))
	defer s.Close()
	c := buildClient(t, clientDescription(t, s.URL, "{anonymous: true}", ""))
	ctx, cancel := c.traversal(context.Background(), false)
	r, e := c.request(ctx, "GET", "/v2/acme/app/manifests/test", nil, 0, "")
	if r != nil {
		r.Body.Close()
	}
	cancel()
	if e == nil {
		t.Fatal("oversized declaration accepted")
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	_, e = c.request(ctx, "GET", "/v2/", nil, 0, "")
	if e == nil {
		t.Fatal("cancellation ignored")
	}
	deadlineCtx, stop := c.traversal(context.Background(), true)
	defer stop()
	deadline, ok := deadlineCtx.Deadline()
	if !ok || time.Until(deadline) > 5*time.Minute {
		t.Fatal("missing traversal deadline")
	}
}
func TestAuthTokenJSONLimits(t *testing.T) {
	for _, body := range []string{`{"token":"x","token":"y"}`, `{"Token":"x"}`, `{"token":"x","access_token":"y"}`, `{"token":"x\r\n"}`, string(bytes.Repeat([]byte(" "), int(ErrorLimit))) + `{"token":"x"}`} {
		t.Run("token", func(t *testing.T) {
			var s *httptest.Server
			s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" {
					w.Header().Set("Content-Type", "application/json")
					io.WriteString(w, body)
					return
				}
				w.Header().Set("Www-Authenticate", `Bearer realm="`+s.URL+`/token"`)
				w.WriteHeader(401)
			}))
			defer s.Close()
			c := buildClient(t, clientDescription(t, s.URL, "{anonymous: true}", ""))
			ctx, cancel := c.traversal(context.Background(), false)
			defer cancel()
			r, e := c.request(ctx, "GET", "/v2/", nil, 0, "")
			if r != nil {
				r.Body.Close()
			}
			if e == nil {
				t.Fatal("unsafe auth JSON accepted")
			}
		})
	}
}

func TestAuthApprovedTLSRealm(t *testing.T) {
	var tokens atomic.Int32
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokens.Add(1)
		u, p, ok := r.BasicAuth()
		if !ok || u != secretCanary || p != secretCanary {
			t.Error("missing Basic credentials")
		}
		if r.URL.Query().Get("scope") != "repository:acme/app:pull" {
			t.Error("reconcile scope widened")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"approved-token"}`)
	}))
	defer tokenServer.Close()
	registry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer approved-token" {
			w.WriteHeader(200)
			return
		}
		w.Header().Set("Www-Authenticate", `Bearer realm="`+tokenServer.URL+`/token",scope="repository:acme/app:pull"`)
		w.WriteHeader(401)
	}))
	defer registry.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	raw := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registry.Certificate().Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tokenServer.Certificate().Raw})...)
	os.WriteFile(ca, raw, 0600)
	c := buildClient(t, clientDescription(t, registry.URL, "{usernameEnv: USER, passwordEnv: PASSWORD}", "caFile: '"+filepath.ToSlash(ca)+"'\ntokenServiceOrigins: ['"+tokenServer.URL+"']\n"))
	ctx, cancel := c.traversal(context.Background(), false)
	defer cancel()
	resp, e := c.request(ctx, "GET", "/v2/", nil, 0, "")
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || tokens.Load() != 1 {
		t.Fatal(resp.StatusCode, tokens.Load())
	}
}
func TestAuthBearerEnvAndDeniedBasic(t *testing.T) {
	for _, bearer := range []bool{false, true} {
		t.Run(map[bool]string{true: "Bearer", false: "denied Basic"}[bearer], func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if bearer {
					if r.Header.Get("Authorization") == "Bearer "+secretCanary {
						w.WriteHeader(200)
						return
					}
					w.Header().Set("Www-Authenticate", `Bearer realm="http://`+r.Host+`/token"`)
				} else {
					w.Header().Set("Www-Authenticate", `Basic realm="synthetic"`)
				}
				w.WriteHeader(401)
			}))
			defer s.Close()
			authConfig := "{usernameEnv: USER, passwordEnv: PASSWORD}"
			if bearer {
				authConfig = "{bearerTokenEnv: TOKEN}"
			}
			c := buildClient(t, clientDescription(t, s.URL, authConfig, ""))
			ctx, cancel := c.traversal(context.Background(), false)
			defer cancel()
			r, e := c.request(ctx, "GET", "/v2/", nil, 0, "")
			if e != nil {
				t.Fatal(e)
			}
			r.Body.Close()
			want := 401
			if bearer {
				want = 200
			}
			if r.StatusCode != want || calls.Load() != 2 {
				t.Fatal(r.StatusCode, calls.Load())
			}
		})
	}
}

type responseTransport func(*http.Request) (*http.Response, error)

func (f responseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type unreadBody struct {
	t      *testing.T
	closed bool
}

func (b *unreadBody) Read([]byte) (int, error) {
	b.t.Fatal("body read before declared limit refusal")
	return 0, io.EOF
}
func (b *unreadBody) Close() error { b.closed = true; return nil }
func TestClientPreallocationAndRequestDeadline(t *testing.T) {
	c := buildClient(t, clientDescription(t, "https://registry.example", "{anonymous: true}", ""))
	ctx, cancel := c.traversal(context.Background(), false)
	defer cancel()
	body := &unreadBody{t: t}
	tr := &safeTransport{options: c.options, base: responseTransport(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 30*time.Second {
			t.Fatal("request deadline missing")
		}
		return &http.Response{StatusCode: 200, ContentLength: DocumentLimit + 1, Header: http.Header{}, Body: body}, nil
	})}
	r, _ := http.NewRequestWithContext(ctx, "GET", "https://registry.example/v2/acme/app/manifests/test", nil)
	resp, e := tr.RoundTrip(r)
	if e == nil || resp != nil || !body.closed || status(ctx) != 200 {
		t.Fatal("preallocation limit lost response fact", resp, e, body.closed, status(ctx))
	}
}
