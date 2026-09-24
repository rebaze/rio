package delivery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/index"
)

func verifiedFixture(t testing.TB) (string, string) {
	t.Helper()
	dir := t.TempDir()
	op := filepath.Join(dir, "bom.json")
	b, err := os.ReadFile("testdata/bom.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(op, b, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	digest := hex.EncodeToString(h[:])
	idx := index.New("test", index.FileRef{Path: "rio.yaml", SHA256: strings.Repeat("a", 64)})
	idx.Artifacts = []index.Artifact{{ID: "application", Input: index.FileRef{Path: "bom.json", SHA256: digest}, Output: index.FileRef{Path: "bom.json", SHA256: digest}, SpecVersion: index.SpecVersions{Input: "1.6", Output: "1.6"}, SchemaValidated: false, Gate: index.GateOK}}
	if _, err = index.Write(dir, idx); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "index.json"), op
}
func TestVerifyContract(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any, map[string]any)
		valid  bool
	}{
		{"valid", func(m, a map[string]any) {}, true},
		{"additive", func(m, a map[string]any) { m["future"] = true; a["future"] = 1 }, true},
		{"missing version", func(m, a map[string]any) { delete(m, "schemaVersion") }, false},
		{"unknown version", func(m, a map[string]any) { m["schemaVersion"] = 2 }, false},
		{"missing tool", func(m, a map[string]any) { delete(m, "tool") }, false},
		{"null validated", func(m, a map[string]any) { a["schemaValidated"] = nil }, false},
		{"missing validated", func(m, a map[string]any) { delete(a, "schemaValidated") }, false},
		{"missing transforms", func(m, a map[string]any) { delete(a, "transforms") }, false},
		{"null findings", func(m, a map[string]any) { a["gateFindings"] = nil }, false},
		{"duplicate IDs", func(m, a map[string]any) { m["artifacts"] = []any{a, a} }, false},
		{"empty ID", func(m, a map[string]any) { a["id"] = "" }, false},
		{"bad digest", func(m, a map[string]any) { a["output"].(map[string]any)["sha256"] = strings.Repeat("A", 64) }, false},
		{"unknown gate", func(m, a map[string]any) { a["gate"] = "unknown" }, false},
		{"failed gate", func(m, a map[string]any) { a["gate"] = "fail" }, false},
		{"negative components", func(m, a map[string]any) { a["components"] = -1 }, false},
		{"absolute output", func(m, a map[string]any) { a["output"].(map[string]any)["path"] = "/tmp/bom.json" }, false},
		{"windows output", func(m, a map[string]any) { a["output"].(map[string]any)["path"] = "C:sbom.json" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip, _ := verifiedFixture(t)
			b, _ := os.ReadFile(ip)
			var m map[string]any
			json.Unmarshal(b, &m)
			a := m["artifacts"].([]any)[0].(map[string]any)
			tc.mutate(m, a)
			b, _ = json.Marshal(m)
			os.WriteFile(ip, b, 0600)
			v, err := Verify(ip, "application", false)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if err != nil && len(v.Payloads()) != 0 {
				t.Fatal("invalid input produced payload")
			}
		})
	}
}
func TestVerifyRawAndGate(t *testing.T) {
	for _, suffix := range []string{" {}", "\nnull"} {
		ip, _ := verifiedFixture(t)
		b, _ := os.ReadFile(ip)
		os.WriteFile(ip, append(b, []byte(suffix)...), 0600)
		if _, err := Verify(ip, "application", true); err == nil {
			t.Fatal("extra JSON accepted")
		}
	}
	ip, op := verifiedFixture(t)
	b, _ := os.ReadFile(ip)
	b = bytes.Replace(b, []byte(`"schemaVersion": 1`), []byte(`"schemaVersion": 1, "schemaVersion": 1`), 1)
	os.WriteFile(ip, b, 0600)
	if _, err := Verify(ip, "application", true); err == nil {
		t.Fatal("duplicate key accepted")
	}
	ip, op = verifiedFixture(t)
	b, _ = os.ReadFile(ip)
	b = bytes.Replace(b, []byte(`"gate": "ok"`), []byte(`"gate": "fail"`), 1)
	os.WriteFile(ip, b, 0600)
	v, err := Verify(ip, "application", true)
	if err != nil || v.Source().Gate != "fail" || !v.Source().AllowFailedGate {
		t.Fatal(err)
	}
	os.WriteFile(op, []byte(`{}`), 0600)
	if _, err := Verify(ip, "application", true); err == nil {
		t.Fatal("tamper accepted")
	}
}
func TestVerifiedPayloadSurvivesSourceReplacement(t *testing.T) {
	ip, op := verifiedFixture(t)
	before, _ := os.ReadFile(op)
	v, err := Verify(ip, "application", false)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(op, []byte(`{"changed":true}`), 0600)
	r := v.Payloads()[0].Open()
	defer r.Close()
	got, _ := io.ReadAll(r)
	if !bytes.Equal(got, before) {
		t.Fatal("payload reopened mutable source")
	}
	ps := v.Payloads()
	ps[0] = Payload{}
	if v.Payloads()[0].Ref().Size != int64(len(before)) {
		t.Fatal("mutable payload slice")
	}
}
func TestVerifyParentPath(t *testing.T) {
	ip, op := verifiedFixture(t)
	dir := filepath.Join(filepath.Dir(ip), "nested")
	os.Mkdir(dir, 0700)
	b, _ := os.ReadFile(ip)
	b = bytes.ReplaceAll(b, []byte(`"path": "bom.json"`), []byte(`"path": "../bom.json"`))
	ip = filepath.Join(dir, "index.json")
	os.WriteFile(ip, b, 0600)
	if _, err := Verify(ip, "application", false); err != nil {
		t.Fatal(op, err)
	}
}
