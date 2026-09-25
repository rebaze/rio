package oci

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthExplicitPrivateOriginWithVerifiedTLS(t *testing.T) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic integration"}, DNSNames: []string{"registry.example"}, IPAddresses: []net.IP{net.ParseIP("10.1.2.3")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	for _, mode := range []string{"approved", "unapproved", "downgrade", "scope"} {
		t.Run(mode, func(t *testing.T) {
			var tokens atomic.Int32
			tokenServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tokens.Add(1)
				u, p, ok := r.BasicAuth()
				if !ok || u != secretCanary || p != secretCanary {
					t.Error("expected Basic credentials absent")
				}
				if r.URL.Query().Get("scope") != "repository:acme/app:pull" {
					t.Error("scope widened")
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"token":"private-origin-token"}`)
			}))
			tokenServer.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
			tokenServer.StartTLS()
			defer tokenServer.Close()
			realm := "https://10.1.2.3/token"
			if mode == "downgrade" {
				realm = "http://10.1.2.3/token"
			}
			registry := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "Bearer private-origin-token" {
					w.WriteHeader(200)
					return
				}
				header := `Bearer realm="` + realm + `",scope="repository:acme/app:pull"`
				if mode == "scope" {
					header = strings.Replace(header, "acme/app", "other/app", 1)
				}
				w.Header().Set("Www-Authenticate", header)
				w.WriteHeader(401)
			}))
			registry.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
			registry.StartTLS()
			defer registry.Close()
			extra := "caFile: '" + filepath.ToSlash(ca) + "'\n"
			if mode != "unapproved" {
				extra += "tokenServiceOrigins: [https://10.1.2.3]\n"
			}
			c := buildClient(t, clientDescription(t, "https://registry.example", "{usernameEnv: USER, passwordEnv: PASSWORD}", extra))
			c.transport.Proxy = nil
			c.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				switch address {
				case "registry.example:443":
					address = registry.Listener.Addr().String()
				case "10.1.2.3:443":
					address = tokenServer.Listener.Addr().String()
				default:
					return nil, fmt.Errorf("unexpected test endpoint")
				}
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}
			ctx, cancel := c.traversal(context.Background(), false)
			defer cancel()
			response, e := c.request(ctx, "GET", "/v2/", nil, 0, "")
			if response != nil {
				response.Body.Close()
			}
			if mode == "approved" {
				if e != nil || response.StatusCode != 200 || tokens.Load() != 1 {
					t.Fatal("explicit private origin was not honored", e, tokens.Load())
				}
			} else if e == nil || tokens.Load() != 0 {
				t.Fatal("unsafe negotiation forwarded credentials", mode, e, tokens.Load())
			}
		})
	}
}
