package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/evidence"
)

func oldRecord(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("../testdata/record-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func fixtureValidator(s record.Snapshot) error {
	if s.Intent.Destination.Type != "fixture" {
		return errors.New("unexpected fixture adapter")
	}
	return nil
}
func TestOldRecordReportsAbsenceAndKeepsUnknown(t *testing.T) {
	raw := oldRecord(t)
	m, e := Load(raw, fixtureValidator)
	if e != nil {
		t.Fatal(e)
	}
	if m.ScopeStatus != "not recorded" || m.ExpectedScope != "not recorded" || m.ArtifactsWithChangeDetail != 0 {
		t.Fatal("old record invented detail", m)
	}
	if m.Artifacts[0].DetailKnown || m.Artifacts[0].Checks != nil || m.Artifacts[0].ChangeStatus != "not recorded" {
		t.Fatal("missing normalization treated as complete")
	}
	if m.Attempts[1].Acknowledgment != "unknown" || !strings.Contains(m.Attempts[0].Transport, "not recorded") {
		t.Fatal("unknown outcome or absent TLS lost")
	}
	html, e := HTML(m)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(html, []byte(delivery.Digest(raw))) {
		t.Fatal("exact provenance missing")
	}
	if _, e = renderHTML(m, 100); e == nil {
		t.Fatal("oversized report accepted")
	}
}
func TestFutureExtensionsRemainUnsupported(t *testing.T) {
	var d evidence.Document
	if e := json.Unmarshal(oldRecord(t), &d); e != nil {
		t.Fatal(e)
	}
	var idx map[string]any
	json.Unmarshal(d.Normalization.Index, &idx)
	idx["normalizationScope"] = map[string]any{"version": 2, "secretFutureMeaning": "not interpreted"}
	a := idx["artifacts"].([]any)[0].(map[string]any)
	a["normalization"] = map[string]any{"version": 2, "changes": "not today's ledger"}
	a["enrichment"] = map[string]any{"version": 2, "changes": []any{}}
	a["checks"] = map[string]any{"version": 2, "evaluations": []any{map[string]any{"outcome": "pass"}}}
	b, _ := json.Marshal(idx)
	ip := filepath.Join(t.TempDir(), "index.json")
	os.WriteFile(ip, b, 0600)
	doc, e := evidence.Collect(ip, nil, "test", nil)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := evidence.Marshal(doc)
	if e != nil {
		t.Fatal(e)
	}
	m, e := Load(raw, nil)
	if e != nil {
		t.Fatal(e)
	}
	if m.Scope != nil || m.ScopeStatus != "unsupported version 2" || m.Artifacts[0].Checks != nil || m.Artifacts[0].DetailKnown {
		t.Fatal("interpreted unsupported extension")
	}
	if !strings.Contains(m.Artifacts[0].Enrichment, "unsupported version 2") {
		t.Fatal("future enrichment interpreted as current evidence")
	}
	if m.Artifacts[0].CheckStatus != "unsupported version 2" || m.Artifacts[0].ChangeStatus != "unsupported version 2" {
		t.Fatal("unsupported evidence not labelled")
	}
}

type refusingWriter struct{}

func (refusingWriter) Write([]byte) (int, error) { return 0, errors.New("closed output") }
func TestTextPropagatesWriteFailure(t *testing.T) {
	m, e := Load(oldRecord(t), fixtureValidator)
	if e != nil {
		t.Fatal(e)
	}
	if e = Text(m, refusingWriter{}); e == nil {
		t.Fatal("terminal output failure ignored")
	}
}

func TestTerminalDoesNotExecuteControlCharactersFromRecordedSpec(t *testing.T) {
	var d evidence.Document
	json.Unmarshal(oldRecord(t), &d)
	var idx map[string]any
	json.Unmarshal(d.Normalization.Index, &idx)
	idx["artifacts"].([]any)[0].(map[string]any)["specVersion"].(map[string]any)["input"] = "\x1b[2J"
	raw, _ := json.Marshal(idx)
	ip := filepath.Join(t.TempDir(), "index.json")
	os.WriteFile(ip, raw, 0600)
	collected, e := evidence.Collect(ip, nil, "test", nil)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = evidence.Marshal(collected)
	if e != nil {
		t.Fatal(e)
	}
	m, e := Load(raw, nil)
	if e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	if e = Text(m, &out); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(out.Bytes(), []byte{0x1b}) {
		t.Fatal("untrusted recorded text can control terminal output")
	}
}

func TestOverridePermissionDoesNotInventAFailedGate(t *testing.T) {
	var original evidence.Document
	json.Unmarshal(oldRecord(t), &original)
	root := t.TempDir()
	ip := filepath.Join(root, "index.json")
	os.WriteFile(ip, original.Normalization.Index, 0600)
	intent := original.Deliveries[0].Intent
	intent.Source.IndexSHA256 = delivery.Digest(original.Normalization.Index)
	intent.Source.AllowFailedGate = true
	path := filepath.Join(root, "attempt")
	w, e := record.Create(path, intent)
	if e != nil {
		t.Fatal(e)
	}
	w.Close()
	d, e := evidence.Collect(ip, []string{path}, "test", fixtureValidator)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := evidence.Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	m, e := Load(raw, fixtureValidator)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, x := range m.Exceptions {
		if strings.Contains(x.Message, "override") {
			found = true
			if !strings.Contains(x.Message, "gate=ok") {
				t.Fatal("override permission misstates actual gate", x)
			}
		}
	}
	if !found {
		t.Fatal("override permission missing")
	}
}
