package manifest_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/rebaze/rio/internal/manifest"
)

func TestProbe4NestedKeys(t *testing.T) {
	cases := map[string]string{
		"nested int key":   "version: 1\nartifacts:\n  - id: a\n    sbom: b.json\n    transforms:\n      - repair-purl:\n          table:\n            5: x\n",
		"nested float key": "version: 1\nartifacts:\n  - id: a\n    sbom: b.json\n    transforms:\n      - repair-purl:\n          table:\n            3.8: x\n",
		"nested bool key":  "version: 1\nartifacts:\n  - id: a\n    sbom: b.json\n    transforms:\n      - repair-purl:\n          table:\n            true: x\n",
		"nested null key":  "version: 1\nartifacts:\n  - id: a\n    sbom: b.json\n    transforms:\n      - repair-purl:\n          table:\n            ~: x\n",
		"nested date key":  "version: 1\nartifacts:\n  - id: a\n    sbom: b.json\n    transforms:\n      - repair-purl:\n          table:\n            2024-01-01: x\n",
		"top int key":      "version: 1\nartifacts:\n  - id: a\n    sbom: b.json\n    transforms:\n      - repair-purl:\n          5: x\n",
		"in list int key":  "version: 1\nartifacts:\n  - id: a\n    sbom: b.json\n    transforms:\n      - repair-purl:\n          items:\n            - 5: x\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "rio.yaml")
			os.WriteFile(p, []byte(src), 0o644)
			m, err := manifest.Load(p)
			if err != nil {
				t.Logf("ERR: %v", err)
				return
			}
			cfg := m.Artifacts[0].Transforms[0].Config
			for k, v := range cfg {
				t.Logf("OK: cfg[%q] = %#v (%T)", k, v, v)
				if mm, ok := v.(map[string]any); ok {
					t.Logf("    -> assert map[string]any OK: %v", mm)
				} else {
					t.Logf("    -> assert map[string]any FAILED, actual %s", fmt.Sprintf("%T", v))
				}
			}
		})
	}
}
