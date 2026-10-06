package oci

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
)

func TestSubmissionBindsActualRepresentationsAndAlreadyPresent(t *testing.T) {
	s := newRegistry(t)
	s.server.Close()
	s.server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	defer s.server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.server.Certificate().Raw}), 0600)
	v, _ := verified(t)
	d := clientDescription(t, s.server.URL, "{anonymous: true}", "caFile: '"+filepath.ToSlash(ca)+"'\n")
	planned, e := (Provider{}).Prepare(d, v.Source(), []delivery.PayloadRef{v.Payloads()[0].Ref()})
	if e != nil {
		t.Fatal(e)
	}
	c := buildClient(t, planned.Description)
	sub, e := c.Submit(context.Background(), v.Payloads())
	if e != nil {
		t.Fatal(e)
	}
	if len(sub.Submitted) != 3 {
		t.Fatalf("missing representation identities: %#v", sub.Submitted)
	}
	found := map[string]delivery.PayloadRef{}
	for _, p := range sub.Submitted {
		found[p.Role] = p
	}
	if found["sbom"].SHA256 != v.Source().OutputSHA256 || found["oci-manifest"].SHA256 != delivery.Digest([]byte(c.options.Publication.ManifestJSON)) || found["oci-config"].SHA256 != delivery.Digest([]byte("{}")) {
		t.Fatal(found)
	}
	if found["oci-manifest"].MediaType != ManifestMediaType || found["sbom"].MediaType != "application/octet-stream" {
		t.Fatal("actual media types missing", found)
	}
	facts, e := ReadTLS(sub.Observations[0])
	if e != nil || facts == nil || !facts.Observed || facts.CertificateVerification != "enforced" {
		t.Fatalf("TLS %#v %v", facts, e)
	}
	sub, e = c.Submit(context.Background(), v.Payloads())
	if e != nil || sub.Disposition != "accepted" || len(sub.Submitted) != 0 {
		t.Fatalf("existing bytes claimed uploaded: %#v %v", sub, e)
	}
}
