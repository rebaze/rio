package oci

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntegrationEnvironmentRequiresExplicitCredentials(t *testing.T) {
	vals := map[string]string{"RIO_OCI_TEST_REGISTRY": "registry.example", "RIO_OCI_TEST_REPOSITORY": "synthetic/repository"}
	lookup := func(k string) string { return vals[k] }
	if _, e := integrationSettings(lookup); e == nil {
		t.Fatal("missing credentials silently accepted")
	}
	vals["RIO_OCI_TEST_AUTH"] = "anonymous"
	if _, e := integrationSettings(lookup); e != nil {
		t.Fatal("explicit anonymous mode refused", e)
	}
	vals["RIO_OCI_TEST_AUTH"] = "basic"
	vals["RIO_OCI_TEST_USERNAME"] = "synthetic-user"
	vals["RIO_OCI_TEST_PASSWORD"] = "secret\r\n"
	if _, e := integrationSettings(lookup); e == nil || strings.Contains(e.Error(), "secret") {
		t.Fatal("bad credential accepted/leaked")
	}
}

func TestIntegrationCrashCleanupPreservesCallerCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("provenance check must not contact upstream") }))
	defer server.Close()
	callerCA := filepath.Join(t.TempDir(), "caller-ca.pem")
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if e := os.WriteFile(callerCA, cert, 0600); e != nil {
		t.Fatal(e)
	}
	upstream := buildClient(t, clientDescription(t, server.URL, "{anonymous: true}", "caFile: "+filepath.ToSlash(callerCA)+"\n"))
	base := integrationConfig{registry: strings.TrimPrefix(server.URL, "https://"), repository: "acme/app", auth: "anonymous", ca: callerCA}
	trace := &integrationTrace{}
	proxyCfg, _, _, _, _ := integrationCrashProxy(t, base, upstream, trace)
	v, _ := verified(t)
	target := integrationTargetFor(t, proxyCfg, v, nil, false, trace, "owned-ca", t.TempDir())
	ownedCA := target.client.options.CAFile
	if ownedCA == callerCA || ownedCA != proxyCfg.ca || base.ca != callerCA {
		t.Fatal("crash target did not isolate its generated proxy CA")
	}
	if e := os.Remove(ownedCA); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(ownedCA); !os.IsNotExist(e) {
		t.Fatal("generated proxy CA was not removed")
	}
	after, e := os.ReadFile(callerCA)
	if e != nil || !bytes.Equal(after, cert) {
		t.Fatal("caller-supplied CA removed or changed")
	}
}
