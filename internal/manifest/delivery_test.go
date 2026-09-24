package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifestDelivery(t *testing.T) {
	base := "version: 1\nartifacts: [{id: app, sbom: missing.json}]\n"
	for _, tc := range []struct {
		name, section string
		valid         bool
	}{
		{"missing", "", true},
		{"minimal", "delivery:\n  targets:\n    security: {type: dependency-track, url: 'https://unreachable.invalid', caFile: missing.pem, apiKeyEnv: UNSET_KEY}\n", true},
		{"unknown adapter offline", "delivery: {targets: {security: {type: future, thing: canary-secret}}}\n", true},
		{"null", "delivery: null\n", false},
		{"empty", "delivery: {}\n", false},
		{"empty targets", "delivery: {targets: {}}\n", false},
		{"unknown envelope", "delivery: {canary-secret: 1}\n", false},
		{"unsafe ID", "delivery: {targets: {canary/secret: {type: dependency-track}}}\n", false},
		{"duplicate", "delivery: {targets: {security: {type: dependency-track, url: canary-secret, url: two}}}\n", false},
		{"alias", "delivery: {targets: {security: &x {type: dependency-track}, other: *x}}\n", false},
		{"exclude type", "delivery: {targets: {security: {type: dependency-track, exclude: [42]}}}\n", false},
		{"override credentials", "delivery: {targets: {security: {type: dependency-track, overrides: {app: {apiKeyEnv: canary-secret}}}}}\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "rio.yaml")
			os.WriteFile(p, []byte(base+tc.section), 0600)
			m, e := Load(p)
			if (e == nil) != tc.valid {
				t.Fatalf("Load=%v", e)
			}
			if e != nil && strings.Contains(e.Error(), "canary") {
				t.Fatalf("unsafe error: %v", e)
			}
			if e == nil && tc.section != "" && m.Delivery.IsZero() {
				t.Fatal("delivery node lost")
			}
		})
	}
}

func TestManifestDeliveryDeclarationLimitOnly(t *testing.T) {
	base := "version: 1\nartifacts: [{id: app, sbom: missing.json}]\n"
	p := filepath.Join(t.TempDir(), "rio.yaml")
	os.WriteFile(p, []byte("#"+strings.Repeat("intake-comment", 90000)+"\n"+base+"delivery: {targets: {security: {type: future}}}\n"), 0600)
	if _, e := Load(p); e != nil {
		t.Fatal("historical intake newly capped", e)
	}
	os.WriteFile(p, []byte(base+"delivery: {targets: {security: {type: future, value: '"+strings.Repeat("x", 1<<20)+"'}}}\n"), 0600)
	if _, e := Load(p); e == nil {
		t.Fatal("oversized delivery accepted")
	}
}
