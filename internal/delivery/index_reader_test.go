package delivery

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// These tests pin the metadata-only contract independently of upload policy.
func TestParseIndexStructureOnlyContract(t *testing.T) {
	ip, op := verifiedFixture(t)
	raw, err := os.ReadFile(ip)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(op); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any, map[string]any)
		valid  bool
	}{
		{"failed gate", func(m, a map[string]any) { a["gate"] = "fail" }, true},
		{"skipped schema", func(m, a map[string]any) { a["schemaValidated"] = false }, true},
		{"additive", func(m, a map[string]any) { m["future"] = json.Number("9007199254740993"); a["future"] = true }, true},
		{"parent paths", func(m, a map[string]any) { a["output"].(map[string]any)["path"] = "../../gone.json" }, true},
		{"null artifacts", func(m, a map[string]any) { m["artifacts"] = nil }, false},
		{"missing artifacts", func(m, a map[string]any) { delete(m, "artifacts") }, false},
		{"null transforms", func(m, a map[string]any) { a["transforms"] = nil }, false},
		{"missing findings", func(m, a map[string]any) { delete(a, "gateFindings") }, false},
		{"duplicate ids", func(m, a map[string]any) { m["artifacts"] = []any{a, a} }, false},
		{"version", func(m, a map[string]any) { m["schemaVersion"] = 2 }, false},
		{"gate", func(m, a map[string]any) { a["gate"] = "unknown" }, false},
		{"digest", func(m, a map[string]any) { a["output"].(map[string]any)["sha256"] = strings.Repeat("A", 64) }, false},
		{"negative count", func(m, a map[string]any) { a["components"] = -1 }, false},
		{"fraction count", func(m, a map[string]any) { a["components"] = 1.5 }, false},
		{"string count", func(m, a map[string]any) { a["components"] = "1" }, false},
		{"absolute", func(m, a map[string]any) { a["output"].(map[string]any)["path"] = "/gone.json" }, false},
		{"volume", func(m, a map[string]any) { a["output"].(map[string]any)["path"] = "C:gone.json" }, false},
		{"alias cannot fill missing", func(m, a map[string]any) { delete(a, "gate"); a["Gate"] = "ok" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m map[string]any
			json.Unmarshal(raw, &m)
			a := m["artifacts"].([]any)[0].(map[string]any)
			tc.mutate(m, a)
			b, _ := json.Marshal(m)
			idx, e := ParseIndex(b)
			if (e == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, e)
			}
			if tc.valid && len(idx.Artifacts) != 1 {
				t.Fatal("lost artifact")
			}
		})
	}
	for _, b := range [][]byte{append(append([]byte{}, raw...), []byte(" {}")...), bytes.Replace(raw, []byte(`"schemaVersion": 1`), []byte(`"schemaVersion": 1,"schemaVersion": 1`), 1)} {
		if _, e := ParseIndex(b); e == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
}
