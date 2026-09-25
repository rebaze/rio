package cli

import (
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery/oci"
	"os"
	"strings"
	"testing"
)

func TestOCIUnifiedSubjectOverride(t *testing.T) {
	descriptor := func(hex string) map[string]any {
		return map[string]any{"digest": "sha256:" + strings.Repeat(hex, 64), "mediaType": oci.ManifestMediaType, "size": 527}
	}
	for _, tc := range []struct {
		name, kind              string
		targetSubject, override any
		valid                   bool
	}{
		{"replace entire subject", "oci", descriptor("1"), map[string]any{"subject": descriptor("2")}, true},
		{"attach one artifact", "oci", nil, map[string]any{"subject": descriptor("2")}, true},
		{"partial subject refused", "oci", descriptor("1"), map[string]any{"subject": map[string]any{"digest": "sha256:" + strings.Repeat("2", 64)}}, false},
		{"DTrack subject refused", "dependency-track", nil, map[string]any{"subject": descriptor("2")}, false},
		{"OCI project refused", "oci", nil, map[string]any{"project": map[string]any{"name": "x", "version": "1"}}, false},
		{"OCI autoCreate refused", "oci", nil, map[string]any{"autoCreate": true}, false},
		{"OCI auth refused", "oci", nil, map[string]any{"auth": map[string]any{"anonymous": true}}, false},
		{"OCI registry refused", "oci", nil, map[string]any{"registry": "other.invalid"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip, cfg := deliveryFixture(t, "https://unused.invalid")
			target := map[string]any{"type": "oci", "registry": "registry.invalid", "repository": "acme/app", "auth": map[string]any{"usernameEnv": "ABSENT_OVERRIDE_USER", "passwordEnv": "ABSENT_OVERRIDE_PASSWORD"}, "caFile": "/missing/never-read-ca.pem"}
			if tc.kind == "dependency-track" {
				target = map[string]any{"type": tc.kind, "url": "https://unused.invalid"}
			}
			if tc.targetSubject != nil {
				target["subject"] = tc.targetSubject
			}
			target["overrides"] = map[string]any{"app": tc.override}
			root := map[string]any{"version": 1, "artifacts": []any{map[string]any{"id": "app", "sbom": "bom.json"}}, "delivery": map[string]any{"targets": map[string]any{"registry": target}}}
			raw, _ := json.Marshal(root)
			os.WriteFile(cfg, raw, 0600)
			_, plan, e := batchPreflight(cfg, deliveryOptions{index: ip})
			if (e == nil) != tc.valid {
				t.Fatalf("valid=%t err=%v", e == nil, e)
			}
			if !tc.valid {
				return
			}
			options, identity, e := oci.ValidateDescription(plan.Jobs[0].Description)
			if e != nil {
				t.Fatal(e)
			}
			want := tc.override.(map[string]any)["subject"].(map[string]any)["digest"].(string)
			if options.Subject == nil || options.Subject.Digest != want || identity.Subject == nil || identity.Subject.Digest != want {
				t.Fatal("override did not replace target descriptor")
			}
			var manifest struct {
				Subject oci.Descriptor `json:"subject"`
			}
			json.Unmarshal([]byte(options.Publication.ManifestJSON), &manifest)
			if manifest.Subject.Digest != want {
				t.Fatal("prepared publication did not use override")
			}
			if code, _, _ := runBatch(t, "delivery", "plan", "--index", ip, "--manifest", cfg); code != 0 {
				t.Fatalf("offline plan refused subject override: %d", code)
			}
		})
	}
}
