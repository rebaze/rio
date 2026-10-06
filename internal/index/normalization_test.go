package index

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizationVersionAndValidation(t *testing.T) {
	valid := `{"version":1,"changes":[{"target":"/components/0/purl","operation":"replace","rule":"repair-purl/p2","before":"pkg:p2/a@1","after":"pkg:maven/a/b@1"}],"bookkeeping":[],"unmapped":[],"skipped":[]}`
	for _, tc := range []struct {
		name, raw string
		valid     bool
	}{
		{"current", valid, true},
		{"unknown opaque", `{"version":2,"future":{"fact":true}}`, true},
		{"missing version", `{}`, false},
		{"missing arrays", `{"version":1}`, false},
		{"bad pointer", strings.Replace(valid, "/components/0/purl", "components.0.purl", 1), false},
		{"bad operation", strings.Replace(valid, "replace", "pretend", 1), false},
		{"unknown known-version field", strings.Replace(valid, `"version":1`, `"version":1,"typo":true`, 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var n Normalization
			err := json.Unmarshal([]byte(tc.raw), &n)
			if (err == nil) != tc.valid {
				t.Fatalf("parse error=%v, valid=%v", err, tc.valid)
			}
			if err == nil && n.Version == 2 {
				out, err := json.Marshal(n)
				if err != nil || string(out) != tc.raw {
					t.Fatalf("opaque evidence changed: %s %v", out, err)
				}
			}
		})
	}
}

func TestNormalizationRejectsComponentPointersOutsideInventory(t *testing.T) {
	for _, target := range []string{"/components/1/purl", "/components/-1/purl", "/components/01/purl", "/components"} {
		t.Run(target, func(t *testing.T) {
			idx := New("test", FileRef{Path: "rio.yaml", SHA256: strings.Repeat("a", 64)})
			idx.Artifacts = []Artifact{{ID: "app", Components: 1, Gate: GateOK, Normalization: &Normalization{Version: 1, Changes: []Change{{Target: target, Operation: "replace", Rule: "repair-purl/p2", Before: "a", After: "b"}}, Bookkeeping: []Change{}, Unmapped: []Unmapped{}, Skipped: []Skipped{}}}}
			if err := idx.Validate(); err == nil {
				t.Fatal("malformed known ledger pointer accepted")
			}
		})
	}
}

func TestNormalizationRejectsUnknownResolutionKind(t *testing.T) {
	raw := `{"version":1,"changes":[{"target":"/components/0/purl","operation":"replace","rule":"repair-purl/p2","before":"a","after":"b","resolution":{"kind":"made-up-source","selector":"x"}}],"bookkeeping":[],"unmapped":[],"skipped":[]}`
	var n Normalization
	if err := json.Unmarshal([]byte(raw), &n); err == nil {
		t.Fatal("unknown source kind interpreted as version 1 evidence")
	}
}
