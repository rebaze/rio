package dtrack

import (
	"context"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
)

func TestTLSObservationBelongsToOriginThroughProxy(t *testing.T) {
	for _, tc := range []struct {
		name                                                    string
		proxyTLS, rejectConnect, originProtocol, lost, verified bool
		observed                                                bool
	}{
		{name: "HTTPS proxy rejects CONNECT", proxyTLS: true, rejectConnect: true},
		{name: "HTTPS proxy origin handshake fails", proxyTLS: true, originProtocol: true},
		{name: "HTTPS proxy successful origin", proxyTLS: true, observed: true},
		{name: "HTTPS proxy verified origin", proxyTLS: true, verified: true, observed: true},
		{name: "HTTPS proxy lost origin response", proxyTLS: true, lost: true, observed: true},
		{name: "HTTP proxy successful origin", observed: true},
		{name: "HTTP proxy lost origin response", lost: true, observed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var origins, connects atomic.Int32
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				origins.Add(1)
				io.Copy(io.Discard, r.Body)
				if r.Header.Get("X-Api-Key") != canary {
					t.Error("origin did not receive credential")
				}
				if tc.lost {
					conn, _, _ := w.(http.Hijacker).Hijack()
					conn.Close()
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if r.Method == "POST" {
					io.WriteString(w, `{"token":"`+token+`"}`)
				} else {
					io.WriteString(w, `{"processing":false}`)
				}
			}))
			if tc.originProtocol {
				origin.Start()
			} else {
				origin.StartTLS()
			}
			defer origin.Close()
			var tunnels sync.WaitGroup
			proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				connects.Add(1)
				if r.Method != "CONNECT" || r.Header.Get("X-Api-Key") != "" {
					t.Error("proxy received origin request or credential")
				}
				if tc.rejectConnect {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				upstream, e := net.Dial("tcp", origin.Listener.Addr().String())
				if e != nil {
					t.Error(e)
					w.WriteHeader(502)
					return
				}
				conn, rw, e := w.(http.Hijacker).Hijack()
				if e != nil {
					upstream.Close()
					t.Error(e)
					return
				}
				tunnels.Add(1)
				defer tunnels.Done()
				defer conn.Close()
				defer upstream.Close()
				io.WriteString(rw, "HTTP/1.1 200 Connection Established\r\n\r\n")
				rw.Flush()
				copied := make(chan struct{})
				go func() { io.Copy(upstream, rw); upstream.Close(); close(copied) }()
				io.Copy(conn, upstream)
				conn.Close()
				<-copied
			}))
			if tc.proxyTLS {
				proxy.StartTLS()
			} else {
				proxy.Start()
			}
			defer func() { proxy.Close(); tunnels.Wait() }()
			destURL := strings.Replace(origin.URL, "http:", "https:", 1)
			if tc.rejectConnect {
				destURL = "https://never-contacted.invalid"
			}
			policy := "\ninsecureSkipVerify: true"
			verification := "disabled"
			if tc.verified {
				cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})
				cert = append(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxy.Certificate().Raw})...)
				ca := filepath.Join(t.TempDir(), "synthetic-origin-and-proxy-ca.pem")
				os.WriteFile(ca, cert, 0600)
				policy = "\ncaFile: " + ca
				verification = "enforced"
			}
			_, target := tlsTarget(t, "url: "+destURL+policy)
			proxyURL, _ := url.Parse(proxy.URL)
			target.(*client).http.Transport.(*http.Transport).Proxy = http.ProxyURL(proxyURL)
			sub, e := target.Submit(context.Background(), payload(t).Payloads())
			success := !tc.rejectConnect && !tc.originProtocol && !tc.lost
			if (e == nil) != success || (sub.Disposition == "accepted") != success {
				t.Fatalf("unexpected submission %s %v", sub.Disposition, e)
			}
			tlsDetail(t, sub.Observations[0], verification, tc.observed)
			observation, e := target.(*client).Observe(context.Background(), []delivery.Reference{{Kind: "dependency-track:event-token", Value: token}})
			if (e == nil) != success {
				t.Fatalf("unexpected observation %v", e)
			}
			tlsDetail(t, observation, verification, tc.observed)
			if connects.Load() != 2 {
				t.Fatalf("proxy requests=%d: replay or missing request", connects.Load())
			}
			expected := int32(2)
			if tc.rejectConnect || tc.originProtocol {
				expected = 0
			}
			if origins.Load() != expected {
				t.Fatalf("origin requests=%d want%d", origins.Load(), expected)
			}
		})
	}
}
