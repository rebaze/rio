package evidence

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func recordMap(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if e := dec.Decode(&m); e != nil {
		t.Fatal(e)
	}
	return m
}
func TestRecordRoundTripWithoutWorkspace(t *testing.T) {
	d, ip, _, _ := collectFixture(t)
	b, e := Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	os.RemoveAll(filepath.Dir(ip))
	var pretty bytes.Buffer
	json.Indent(&pretty, b, "", "  ")
	got, e := Parse(pretty.Bytes(), validateFixture)
	if e != nil {
		t.Fatal(e)
	}
	out, e := Marshal(got)
	if e != nil || !bytes.Equal(b, out) {
		t.Fatal("standalone roundtrip lost evidence", e)
	}
	if got.Normalization.SBOMBytesVerification != "not-performed" {
		t.Fatal("claimed file check")
	}
}
func TestParseRefusesContradictions(t *testing.T) {
	d, _, _, _ := collectFixture(t)
	original, e := Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"data", "size", "hash", "kind", "media", "id", "encoding", "duplicate-source", "unreferenced-source", "missing-source", "endpoint", "gate", "integer", "summary", "event-sequence", "null", "unknown-root", "case-alias", "version", "root-kind", "note-assertion", "note-range", "unknown-adapter"} {
		t.Run(kind, func(t *testing.T) {
			m := recordMap(t, original)
			ev := m["evidence"].([]any)
			s := ev[0].(map[string]any)
			norm := m["normalization"].(map[string]any)
			ds := m["deliveries"].([]any)
			switch kind {
			case "data":
				s["data"] = "!!!!"
			case "size":
				s["size"] = 1
			case "hash":
				s["sha256"] = strings.Repeat("f", 64)
			case "kind":
				s["kind"] = "future-kind"
			case "media":
				s["mediaType"] = "text/json"
			case "id":
				s["id"] = "other"
			case "encoding":
				s["encoding"] = "hex"
			case "duplicate-source":
				m["evidence"] = append(ev, ev[0])
			case "unreferenced-source":
				m["evidence"] = append(ev, map[string]any{"id": "unreferenced", "kind": "normalization-index", "mediaType": "application/json", "sha256": delivery.Digest([]byte("{}")), "size": 2, "encoding": "base64", "data": "e30="})
			case "missing-source":
				m["evidence"] = ev[1:]
			case "endpoint":
				ds[0].(map[string]any)["intent"].(map[string]any)["destination"].(map[string]any)["identity"].(map[string]any)["url"] = "https://edited.invalid"
			case "gate":
				norm["index"].(map[string]any)["artifacts"].([]any)[0].(map[string]any)["gate"] = "fail"
			case "integer":
				norm["index"].(map[string]any)["future"].(map[string]any)["integer"] = json.Number("9007199254740992")
			case "summary":
				ds[0].(map[string]any)["summary"].(map[string]any)["acknowledgment"] = "rejected"
			case "event-sequence":
				ds[0].(map[string]any)["events"].([]any)[0].(map[string]any)["sequence"] = 8
			case "null":
				m["deliveries"] = nil
			case "unknown-root":
				m["future"] = true
			case "case-alias":
				m["SchemaVersion"] = 1
			case "version":
				m["schemaVersion"] = 2
			case "root-kind":
				m["kind"] = "other"
			case "note-assertion", "note-range":
				note := map[string]any{"code": "orphan-temporary-files", "attemptId": ds[0].(map[string]any)["attemptId"], "count": 1, "assertion": "collector"}
				if kind == "note-assertion" {
					note["assertion"] = "verified"
				} else {
					note["count"] = 20001
				}
				m["coverage"].(map[string]any)["collectionNotes"] = []any{note}
			case "unknown-adapter":
				for _, item := range ev[1:] {
					src := item.(map[string]any)
					raw, _ := base64.StdEncoding.DecodeString(src["data"].(string))
					raw = bytes.ReplaceAll(raw, []byte(`"fixture"`), []byte(`"unknown"`))
					src["data"] = base64.StdEncoding.EncodeToString(raw)
					src["sha256"] = delivery.Digest(raw)
					src["size"] = len(raw)
				}
			}
			b, _ := json.Marshal(m)
			if _, e := Parse(b, validateFixture); e == nil {
				t.Fatal("contradiction accepted")
			}
		})
	}
	for _, bad := range [][]byte{append(append([]byte{}, original...), []byte("{}")...), bytes.Replace(original, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1)} {
		if _, e := Parse(bad, validateFixture); e == nil {
			t.Fatal("duplicate/trailing accepted")
		}
	}
}
func TestMarshalRefusesEditedProjection(t *testing.T) {
	d, _, _, _ := collectFixture(t)
	d.Deliveries[0].Summary.Acknowledgment = "rejected"
	if _, e := Marshal(d); e == nil {
		t.Fatal("inconsistent in-memory document serialized")
	}
}
func TestRecordLimitsBeforeDecode(t *testing.T) {
	d, _, _, _ := collectFixture(t)
	b, _ := Marshal(d)
	for _, kind := range []string{"declared-over", "encoded-over", "underdeclared", "source-count", "delivery-count"} {
		t.Run(kind, func(t *testing.T) {
			m := recordMap(t, b)
			s := m["evidence"].([]any)[0].(map[string]any)
			switch kind {
			case "declared-over":
				s["size"] = SourceLimit + 1
			case "encoded-over":
				s["size"] = 1
				s["data"] = strings.Repeat("A", 1<<20)
			case "underdeclared":
				s["size"] = 0
			case "source-count":
				ev := m["evidence"].([]any)
				for len(ev) <= MaxEvents+1 {
					ev = append(ev, ev[0])
				}
				m["evidence"] = ev
			case "delivery-count":
				ds := m["deliveries"].([]any)
				for len(ds) <= MaxJournals {
					ds = append(ds, ds[0])
				}
				m["deliveries"] = ds
			}
			bad, _ := json.Marshal(m)
			if _, e := Parse(bad, validateFixture); e == nil {
				t.Fatal("limit ignored")
			}
		})
	}
}

func TestParseRefusesInvalidEmbeddedEventWithCorrectDigest(t *testing.T) {
	d, _, _, _ := collectFixture(t)
	for n := range d.Evidence {
		if d.Evidence[n].Kind == "delivery-event" {
			s := &d.Evidence[n]
			raw, _ := base64.StdEncoding.DecodeString(s.Data)
			raw = bytes.Replace(raw, []byte(`"sequence": 0`), []byte(`"sequence": 9`), 1)
			s.Data = base64.StdEncoding.EncodeToString(raw)
			s.SHA256 = delivery.Digest(raw)
			s.Size = int64(len(raw))
			break
		}
	}
	b, _ := json.Marshal(d)
	if _, e := Parse(b, validateFixture); e == nil {
		t.Fatal("correct raw digest bypassed journal validation")
	}
}
func TestParseCollectorNotesAreClaims(t *testing.T) {
	d, _, _, _ := collectFixture(t)
	d.Coverage.CollectionNotes = []CollectionNote{{Code: "orphan-temporary-files", AttemptID: d.Deliveries[0].AttemptID, Count: 2, Assertion: "collector"}}
	b, _ := json.Marshal(d)
	got, e := Parse(b, validateFixture)
	if e != nil || got.Coverage.CollectionNotes[0].Assertion != "collector" {
		t.Fatal("collector claim lost or promoted", e)
	}
}
func TestMarshalGolden(t *testing.T) {
	ip, p, q := fixture(t)
	for j, path := range []string{p, q} {
		for n := 0; n < 2; n++ {
			file := filepath.Join(path, fmt.Sprintf("%020d.json", n))
			b, e := os.ReadFile(file)
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				t.Fatal(e)
			}
			var ev record.Event
			json.Unmarshal(b, &ev)
			ev.AttemptID = strings.Repeat(fmt.Sprint(j+1), 32)
			ev.ObservedAt = "2026-09-24T12:00:00Z"
			b, _ = json.Marshal(ev)
			os.WriteFile(file, append(b, '\n'), 0600)
		}
	}
	d, e := Collect(ip, []string{p, q}, "collector", validateFixture)
	if e != nil {
		t.Fatal(e)
	}
	b, e := Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	path := "testdata/record-v1.json"
	if os.Getenv("RIO_UPDATE_GOLDEN") == "1" {
		os.MkdirAll("testdata", 0755)
		os.WriteFile(path, b, 0600)
	}
	want, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(b, want) {
		t.Fatal("deterministic record changed")
	}
}
func TestRecordRawBudgetExactAndOverflow(t *testing.T) {
	ip, p, _ := fixture(t)
	idx, _ := os.ReadFile(ip)
	idx = append(idx, bytes.Repeat([]byte(" "), int(delivery.IndexLimit)-len(idx))...)
	os.WriteFile(ip, idx, 0600)
	mutateIntent(t, p, func(i *record.Intent) { i.Source.IndexSHA256 = delivery.Digest(idx) })
	raw, _ := os.ReadFile(filepath.Join(p, "00000000000000000000.json"))
	var first record.Event
	json.Unmarshal(raw, &first)
	for n := 0; n < 16; n++ {
		var b []byte
		if n < 2 {
			b, _ = os.ReadFile(filepath.Join(p, fmt.Sprintf("%020d.json", n)))
		} else {
			data, _ := json.Marshal(record.Reconciliation{Observation: delivery.Observation{Kind: "unavailable", Value: "unavailable", Origin: "local", Code: "query_failed", References: []delivery.Reference{}}, ConfigSHA256: strings.Repeat("a", 64)})
			b, _ = json.Marshal(record.Event{SchemaVersion: 1, Sequence: n, AttemptID: first.AttemptID, ObservedAt: first.ObservedAt, Kind: "reconciliation", Data: data})
		}
		b = append(b, bytes.Repeat([]byte(" "), int(record.EventLimit)-len(b))...)
		os.WriteFile(filepath.Join(p, fmt.Sprintf("%020d.json", n)), b, 0600)
	}
	d, e := Collect(ip, []string{p}, "collector", validateFixture)
	if e != nil {
		t.Fatal("exact 32 MiB source budget refused", e)
	}
	b, e := Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Parse(b, validateFixture); e != nil {
		t.Fatal("exact raw budget inspection failed", e)
	}
	os.WriteFile(filepath.Join(p, "00000000000000000016.json"), []byte("{}"), 0600)
	if _, e = Collect(ip, []string{p}, "collector", validateFixture); e == nil {
		t.Fatal("aggregate overflow accepted")
	}
}

func TestParseRejectsLatestActivityEdits(t *testing.T) {
	ip, p, _ := fixture(t)
	w, e := record.Open(p)
	if e != nil {
		t.Fatal(e)
	}
	for _, value := range []string{"processing", "not-observed"} {
		b, _ := json.Marshal(record.Reconciliation{Observation: delivery.Observation{Kind: "activity", Value: value, Origin: "receiver", Code: "activity_observed", References: []delivery.Reference{}}, ConfigSHA256: strings.Repeat("a", 64)})
		if e = w.Append("reconciliation", b); e != nil {
			t.Fatal(e)
		}
	}
	w.Close()
	d, e := Collect(ip, []string{p}, "collector", validateFixture)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := Marshal(d)
	m := recordMap(t, b)
	m["deliveries"].([]any)[0].(map[string]any)["summary"].(map[string]any)["latestActivity"].(map[string]any)["observation"].(map[string]any)["value"] = "processing"
	b, _ = json.Marshal(m)
	if _, e = Parse(b, validateFixture); e == nil {
		t.Fatal("edited activity accepted")
	}
}
func TestRecordFileLimitBeforeParsingOrEncoding(t *testing.T) {
	d, _, _, _ := collectFixture(t)
	d.Tool.Version = strings.Repeat("x", int(FileLimit))
	if _, e := Marshal(d); e == nil {
		t.Fatal("output size exceeded")
	}
	if _, e := Parse([]byte(d.Tool.Version+"x"), validateFixture); e == nil {
		t.Fatal("serialized input size exceeded")
	}
}
func TestParseRequiredFieldsAndReferences(t *testing.T) {
	d, _, _, _ := collectFixture(t)
	b, _ := Marshal(d)
	for _, kind := range []string{"missing-root", "missing-evidence", "null-source", "null-intent", "null-source-ref", "null-payload", "wrong-kind-ref", "reverse-deliveries", "reverse-sources", "context"} {
		t.Run(kind, func(t *testing.T) {
			m := recordMap(t, b)
			ds := m["deliveries"].([]any)
			switch kind {
			case "missing-root":
				delete(m, "coverage")
			case "missing-evidence":
				delete(m, "evidence")
			case "null-source":
				m["evidence"].([]any)[0] = nil
			case "null-intent":
				ds[0].(map[string]any)["intent"] = nil
			case "null-source-ref":
				ds[0].(map[string]any)["intent"].(map[string]any)["source"] = nil
			case "null-payload":
				ds[0].(map[string]any)["intent"].(map[string]any)["payloads"] = []any{nil}
			case "wrong-kind-ref":
				ds[0].(map[string]any)["evidenceIds"].([]any)[0] = "normalization-index"
			case "reverse-deliveries":
				ds[0], ds[1] = ds[1], ds[0]
			case "reverse-sources":
				es := m["evidence"].([]any)
				es[0], es[1] = es[1], es[0]
			case "context":
				m["normalization"].(map[string]any)["index"].(map[string]any)["artifacts"].([]any)[0].(map[string]any)["context"] = map[string]any{"invented": "authenticated"}
			}
			bad, _ := json.Marshal(m)
			if _, e := Parse(bad, validateFixture); e == nil {
				t.Fatal("invalid reference/shape accepted")
			}
		})
	}
}
