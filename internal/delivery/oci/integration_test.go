package oci

import (
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
