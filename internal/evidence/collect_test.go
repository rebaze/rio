package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/index"
)

func fixture(t testing.TB) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	h := strings.Repeat("a", 64)
	idx := index.New("normalizer", index.FileRef{Path: "gone/rio.yaml", SHA256: h})
	idx.Artifacts = []index.Artifact{{ID: "app", Input: index.FileRef{Path: "gone/input.json", SHA256: h}, Output: index.FileRef{Path: "gone/output.json", SHA256: h}, SpecVersion: index.SpecVersions{Input: "1.5", Output: "1.6"}, Gate: index.GateOK}, {ID: "without", Input: index.FileRef{Path: "in", SHA256: h}, Output: index.FileRef{Path: "out", SHA256: h}, SpecVersion: index.SpecVersions{Input: "1.6", Output: "1.6"}, Gate: index.GateFail}}
	if _, e := index.Write(dir, idx); e != nil {
		t.Fatal(e)
	}
	ip := filepath.Join(dir, "index.json")
	raw, _ := os.ReadFile(ip)
	var m map[string]json.RawMessage
	json.Unmarshal(raw, &m)
	m["future"] = json.RawMessage(`{"integer":9007199254740993,"html":"<source>"}`)
	raw, _ = json.Marshal(m)
	os.WriteFile(ip, raw, 0600)
	makeAttempt := func(name, disposition string) string {
		p := filepath.Join(dir, name)
		i := fixtureIntent(raw)
		w, e := record.Create(p, i)
		if e != nil {
			t.Fatal(e)
		}
		if disposition != "" {
			sub := delivery.Submission{Disposition: disposition, References: []delivery.Reference{}, Observations: []delivery.Observation{}}
			if disposition != "unknown" {
				sub.Observations = append(sub.Observations, delivery.Observation{Kind: "acknowledgment", Value: disposition, Origin: "receiver", Code: "upload_response", References: []delivery.Reference{}})
			}
			b, _ := json.Marshal(sub)
			if e = w.Append("submission", b); e != nil {
				t.Fatal(e)
			}
		}
		if e = w.Close(); e != nil {
			t.Fatal(e)
		}
		return p
	}
	return ip, makeAttempt("first", "accepted"), makeAttempt("second", "")
}
func fixtureIntent(raw []byte) record.Intent {
	h := strings.Repeat("a", 64)
	return record.Intent{RioVersion: "normalizer", Source: delivery.Source{IndexSHA256: delivery.Digest(raw), ArtifactID: "app", OutputSHA256: h, Gate: "ok"}, Payloads: []delivery.PayloadRef{{Role: "sbom", MediaType: "application/vnd.cyclonedx+json", SHA256: h, SourceSHA256: h, Size: 10, Transformation: "identity"}}, Binding: "app", Destination: delivery.Description{Type: "fixture", DestinationName: "security", Identity: json.RawMessage(`{"url":"https://unreachable.invalid","project":"app"}`), Options: json.RawMessage(`{"allowHTTP":false,"apiKeyEnv":"NEVER_READ","caFile":"/missing"}`), CredentialRefs: []string{"NEVER_READ"}, Capabilities: []string{"submit"}}, ConfigSHA256: h}
}
func validateFixture(s record.Snapshot) error {
	if s.Intent.Destination.Type != "fixture" {
		return delivery.Fail("unsupported_adapter", "fixture")
	}
	return nil
}
func collectFixture(t *testing.T) (Document, string, string, string) {
	t.Helper()
	ip, p, q := fixture(t)
	d, e := Collect(ip, []string{p, q}, "collector", validateFixture)
	if e != nil {
		t.Fatal(e)
	}
	return d, ip, p, q
}
func TestCollectOrderAndLocationDoNotChangeBytes(t *testing.T) {
	d, ip, p, q := collectFixture(t)
	a, e := Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	b, e := Collect(ip, []string{q, p}, "collector", validateFixture)
	if e != nil {
		t.Fatal(e)
	}
	bb, e := Marshal(b)
	if e != nil || !bytes.Equal(a, bb) {
		t.Fatal("argument order changes evidence", e)
	}
	moved := filepath.Join(t.TempDir(), "moved")
	if e = os.Rename(filepath.Dir(ip), moved); e != nil {
		t.Fatal(e)
	}
	c, e := Collect(filepath.Join(moved, "index.json"), []string{filepath.Join(moved, "first"), filepath.Join(moved, "second")}, "collector", validateFixture)
	if e != nil {
		t.Fatal(e)
	}
	cc, _ := Marshal(c)
	if !bytes.Equal(a, cc) {
		t.Fatal("source location changes evidence")
	}
	if !bytes.Contains(a, []byte("9007199254740993")) || bytes.Contains(a, []byte(`\u003c`)) {
		t.Fatal("lost additive numbers or escaped HTML")
	}
}
func TestCollectCoverageAndObservations(t *testing.T) {
	ip, p, q := fixture(t)
	w, e := record.Open(p)
	if e != nil {
		t.Fatal(e)
	}
	for _, o := range []delivery.Observation{{Kind: "activity", Value: "processing", Origin: "receiver", Code: "processing", References: []delivery.Reference{}}, {Kind: "unavailable", Value: "unavailable", Origin: "local", Code: "query_failed", References: []delivery.Reference{}}} {
		b, _ := json.Marshal(record.Reconciliation{Observation: o, ConfigSHA256: strings.Repeat("a", 64)})
		if e = w.Append("reconciliation", b); e != nil {
			t.Fatal(e)
		}
	}
	w.Close()
	os.WriteFile(filepath.Join(p, ".event-orphan.tmp"), []byte("not evidence"), 0600)
	d, e := Collect(ip, []string{p, q}, "collector", validateFixture)
	if e != nil {
		t.Fatal(e)
	}
	if d.Coverage.SelectedDeliveryCount != 2 || strings.Join(d.Coverage.ArtifactIDsWithoutSelectedDeliveries, ",") != "without" || len(d.Coverage.CollectionNotes) != 1 {
		t.Fatal("wrong coverage", d.Coverage)
	}
	for _, x := range d.Deliveries {
		if x.Summary.Acknowledgment == "accepted" {
			if x.Summary.LatestActivity.Sequence != 2 || x.Summary.LastObservation.Sequence != 3 || x.Summary.LastObservation.Observation.Kind != "unavailable" {
				t.Fatal("flattened observations")
			}
		} else if x.Summary.Acknowledgment != "unknown" {
			t.Fatal("invented outcome")
		}
	}
	zero, e := Collect(ip, nil, "collector", validateFixture)
	if e != nil || len(zero.Deliveries) != 0 || len(zero.Coverage.ArtifactIDsWithoutSelectedDeliveries) != 2 {
		t.Fatal("zero selection", e)
	}
}
func mutateIntent(t *testing.T, p string, f func(*record.Intent)) {
	t.Helper()
	file := filepath.Join(p, "00000000000000000000.json")
	b, _ := os.ReadFile(file)
	var ev record.Event
	json.Unmarshal(b, &ev)
	var i record.Intent
	json.Unmarshal(ev.Data, &i)
	f(&i)
	ev.Data, _ = json.Marshal(i)
	b, _ = json.Marshal(ev)
	if e := os.WriteFile(file, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func TestCollectJoinRefusals(t *testing.T) {
	for _, kind := range []string{"raw-index", "artifact", "output", "gate", "schema", "payload", "adapter", "duplicate", "missing"} {
		t.Run(kind, func(t *testing.T) {
			ip, p, q := fixture(t)
			paths := []string{p, q}
			switch kind {
			case "raw-index":
				f, _ := os.OpenFile(ip, os.O_APPEND|os.O_WRONLY, 0600)
				f.WriteString("\n")
				f.Close()
			case "duplicate":
				paths = append(paths, p)
			case "missing":
				paths = append(paths, p+"-missing")
			default:
				mutateIntent(t, p, func(i *record.Intent) {
					switch kind {
					case "artifact":
						i.Source.ArtifactID = "missing"
					case "output":
						i.Source.OutputSHA256 = strings.Repeat("b", 64)
						i.Payloads[0].SHA256 = i.Source.OutputSHA256
						i.Payloads[0].SourceSHA256 = i.Source.OutputSHA256
					case "gate":
						i.Source.Gate = "fail"
						i.Source.AllowFailedGate = true
					case "schema":
						i.Source.SchemaValidated = true
					case "payload":
						i.Payloads[0].SourceSHA256 = strings.Repeat("b", 64)
					case "adapter":
						i.Destination.Type = "other"
					}
				})
			}
			if _, e := Collect(ip, paths, "collector", validateFixture); e == nil {
				t.Fatal("invalid selected source silently accepted")
			}
		})
	}
}
func TestRetryPrefixAndMissingCoverage(t *testing.T) {
	ip, p, q := fixture(t)
	prior, e := record.Read(p)
	if e != nil {
		t.Fatal(e)
	}
	mutateIntent(t, q, func(i *record.Intent) {
		i.Retry = &record.Retry{AttemptID: prior.Events[0].AttemptID, SHA256: prior.SHA256, PathHint: "/never/follow"}
	})
	w, e := record.Open(p)
	if e != nil {
		t.Fatal(e)
	}
	r, _ := json.Marshal(record.Reconciliation{Observation: delivery.Observation{Kind: "unavailable", Value: "unavailable", Origin: "local", Code: "query_failed", References: []delivery.Reference{}}, ConfigSHA256: strings.Repeat("a", 64)})
	w.Append("reconciliation", r)
	w.Close()
	if _, e = Collect(ip, []string{p, q}, "collector", validateFixture); e != nil {
		t.Fatal("valid older prefix refused", e)
	}
	d, e := Collect(ip, []string{q}, "collector", validateFixture)
	if e != nil || strings.Join(d.Coverage.RetryAttemptIDsNotIncluded, ",") != prior.Events[0].AttemptID {
		t.Fatal("missing ancestry hidden", e)
	}
	mutateIntent(t, q, func(i *record.Intent) { i.Retry.SHA256 = strings.Repeat("f", 64) })
	if _, e = Collect(ip, []string{p, q}, "collector", validateFixture); e == nil {
		t.Fatal("wrong prefix accepted")
	}
}

func TestRetryRefusesSelfCycleAndPolicyDrift(t *testing.T) {
	for _, kind := range []string{"self", "cycle", "policy", "payload", "source"} {
		t.Run(kind, func(t *testing.T) {
			ip, p, q := fixture(t)
			prior, _ := record.Read(p)
			next, _ := record.Read(q)
			mutateIntent(t, q, func(i *record.Intent) {
				i.Retry = &record.Retry{AttemptID: prior.Events[0].AttemptID, SHA256: prior.SHA256}
				switch kind {
				case "self":
					i.Retry.AttemptID = next.Events[0].AttemptID
				case "policy":
					i.Destination.Options = json.RawMessage(`{"allowHTTP":true}`)
				case "payload":
					i.Payloads[0].Size = 11
				case "source":
					i.Source.AllowFailedGate = true
				}
			})
			if kind == "cycle" {
				mutateIntent(t, p, func(i *record.Intent) {
					i.Retry = &record.Retry{AttemptID: next.Events[0].AttemptID, SHA256: next.SHA256}
				})
			}
			if _, e := Collect(ip, []string{p, q}, "collector", validateFixture); e == nil {
				t.Fatal("invalid retry accepted")
			}
		})
	}
}
func TestCollectDuplicateCopiesAndAliases(t *testing.T) {
	ip, p, _ := fixture(t)
	q := filepath.Join(t.TempDir(), "copy")
	os.Mkdir(q, 0700)
	for _, n := range []string{"00000000000000000000.json", "00000000000000000001.json"} {
		b, _ := os.ReadFile(filepath.Join(p, n))
		os.WriteFile(filepath.Join(q, n), b, 0600)
	}
	for _, paths := range [][]string{{p, q}, {p, filepath.Join(p, ".")}} {
		if _, e := Collect(ip, paths, "collector", validateFixture); e == nil {
			t.Fatal("duplicate attempt counted twice")
		}
	}
}
func TestCollectRejectedAndUnknownAreFacts(t *testing.T) {
	for _, status := range []string{"rejected", "unknown"} {
		t.Run(status, func(t *testing.T) {
			ip, p, _ := fixture(t)
			file := filepath.Join(p, "00000000000000000001.json")
			b, _ := os.ReadFile(file)
			b = bytes.ReplaceAll(b, []byte("accepted"), []byte(status))
			os.WriteFile(file, b, 0600)
			d, e := Collect(ip, []string{p}, "collector", validateFixture)
			if e != nil || d.Deliveries[0].Summary.Acknowledgment != status {
				t.Fatal("outcome treated as execution failure", e)
			}
		})
	}
}
func TestCollectSourceAndJournalLimits(t *testing.T) {
	ip, _, _ := fixture(t)
	if _, e := Collect(ip, make([]string, 257), "collector", validateFixture); e == nil {
		t.Fatal("journal limit ignored")
	}
	f, _ := os.OpenFile(ip, os.O_WRONLY, 0600)
	f.Truncate(delivery.IndexLimit + 1)
	f.Close()
	if _, e := Collect(ip, nil, "collector", validateFixture); e == nil {
		t.Fatal("index byte limit ignored")
	}
}

func TestCollectCombinedEventLimit(t *testing.T) {
	ip, p, q := fixture(t)
	paths := []string{p, q}
	for _, path := range paths {
		raw, _ := os.ReadFile(filepath.Join(path, "00000000000000000000.json"))
		var first record.Event
		json.Unmarshal(raw, &first)
		if path == q {
			sub := delivery.Submission{Disposition: "unknown", References: []delivery.Reference{}, Observations: []delivery.Observation{}}
			data, _ := json.Marshal(sub)
			b, _ := json.Marshal(record.Event{SchemaVersion: 1, Sequence: 1, AttemptID: first.AttemptID, ObservedAt: first.ObservedAt, Kind: "submission", Data: data})
			os.WriteFile(filepath.Join(path, "00000000000000000001.json"), b, 0600)
		}
		data, _ := json.Marshal(record.Reconciliation{Observation: delivery.Observation{Kind: "unavailable", Value: "unavailable", Origin: "local", Code: "query_failed", References: []delivery.Reference{}}, ConfigSHA256: strings.Repeat("a", 64)})
		for n := 2; n < 5000; n++ {
			b, _ := json.Marshal(record.Event{SchemaVersion: 1, Sequence: n, AttemptID: first.AttemptID, ObservedAt: first.ObservedAt, Kind: "reconciliation", Data: data})
			if e := os.WriteFile(filepath.Join(path, fmt.Sprintf("%020d.json", n)), b, 0600); e != nil {
				t.Fatal(e)
			}
		}
	}
	d, e := Collect(ip, paths, "collector", validateFixture)
	if e != nil || len(d.Evidence) != 10001 {
		t.Fatal("exact aggregate event count refused", e)
	}
	last, _ := os.ReadFile(filepath.Join(q, "00000000000000004999.json"))
	last = bytes.Replace(last, []byte(`"sequence":4999`), []byte(`"sequence":5000`), 1)
	os.WriteFile(filepath.Join(q, "00000000000000005000.json"), last, 0600)
	if _, e = Collect(ip, paths, "collector", validateFixture); e == nil {
		t.Fatal("aggregate event count truncated or ignored")
	}
}
func TestCollectExactJournalCount(t *testing.T) {
	ip, p, _ := fixture(t)
	raw, _ := os.ReadFile(filepath.Join(p, "00000000000000000000.json"))
	var first record.Event
	json.Unmarshal(raw, &first)
	parent := t.TempDir()
	paths := []string{}
	for n := 0; n < 256; n++ {
		path := filepath.Join(parent, fmt.Sprint(n))
		os.Mkdir(path, 0700)
		first.AttemptID = fmt.Sprintf("%032x", n)
		b, _ := json.Marshal(first)
		os.WriteFile(filepath.Join(path, "00000000000000000000.json"), b, 0600)
		paths = append(paths, path)
	}
	d, e := Collect(ip, paths, "collector", validateFixture)
	if e != nil || len(d.Deliveries) != 256 {
		t.Fatal("exact journal limit refused", e)
	}
	b, e := Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Parse(b, validateFixture); e != nil {
		t.Fatal("exact journal inspection refused", e)
	}
	paths = append(paths, paths[0])
	if _, e = Collect(ip, paths, "collector", validateFixture); e == nil {
		t.Fatal("journal limit ignored")
	}
}

func TestMarshalDisablesHTMLEscapingInReadableEvents(t *testing.T) {
	ip, p, _ := fixture(t)
	mutateIntent(t, p, func(i *record.Intent) {
		i.Destination.Identity = json.RawMessage(`{"url":"https://example.invalid/?a=1&b=2"}`)
		i.Destination.Options = json.RawMessage(`{"marker":"<original>"}`)
	})
	d, e := Collect(ip, []string{p}, "collector", validateFixture)
	if e != nil {
		t.Fatal(e)
	}
	b, e := Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(b, []byte(`\u0026`)) || bytes.Contains(b, []byte(`\u003c`)) {
		t.Fatal("readable raw JSON escaped HTML despite canonical output contract")
	}
}
