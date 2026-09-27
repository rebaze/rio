package receipt

import (
	"bytes"
	"strings"
	"testing"
)

func fixture() Document {
	return Document{Kind: Kind, SchemaVersion: 1, RioVersion: "0.7.0", Run: Run{ID: "run-1", Operation: "pipeline", StartedAt: "2026-09-27T12:00:00Z", FinishedAt: "2026-09-27T12:00:01Z", Outcome: "success", Stages: map[string]string{"intake": "completed", "delivery": "completed"}}, Artifacts: []Artifact{{ID: "api", State: "completed", Input: &Bytes{Path: "api.cdx.json", SHA256: strings.Repeat("a", 64), Size: 123}, Output: &Bytes{SHA256: strings.Repeat("b", 64), Size: 234}, Checks: &Checks{Mode: "fail", Gate: "pass", Schema: "pass", ComponentScope: "including-nested", ComponentsEvaluated: 1, ComponentRequirements: []string{"name"}, ComponentEvaluation: "evaluated"}}}, Targets: map[string]Target{"security": {Type: "dependency-track", URL: "https://receiver.example.org"}}, Deliveries: []Delivery{{ArtifactID: "api", Target: "security", AttemptID: "attempt-1", State: "accepted", RequestMayHaveOccurred: true, AttemptedAt: "2026-09-27T12:00:00Z", Submitted: []Bytes{{ArtifactOutput: "api"}}, Transport: Transport{Scheme: "https", CertificateVerification: "enforced", TLSObserved: boolptr(true)}, Responses: []Response{{Kind: "acknowledgment", Value: "accepted", HTTPStatus: 200, ObservedAt: "2026-09-27T12:00:01Z", References: []Reference{{Kind: "dependency-track:event-token", Value: "11111111-1111-4111-8111-111111111111"}}}}}}}
}
func boolptr(v bool) *bool { return &v }

func TestRoundTripDeterministicReadable(t *testing.T) {
	d := fixture()
	a, e := Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(a, []byte("\n  \"kind\"")) {
		t.Fatal("not readable indented JSON")
	}
	parsed, e := Parse(a)
	if e != nil {
		t.Fatal(e)
	}
	b, e := Marshal(parsed)
	if e != nil || !bytes.Equal(a, b) {
		t.Fatalf("unstable: %v", e)
	}
}
func TestRejectInvalidContract(t *testing.T) {
	tests := map[string]func(*Document){
		"old kind":                  func(d *Document) { d.Kind = "rio-evidence-record" },
		"old version":               func(d *Document) { d.SchemaVersion = 2 },
		"dangling artifact":         func(d *Document) { d.Deliveries[0].ArtifactID = "missing" },
		"dangling target":           func(d *Document) { d.Deliveries[0].Target = "missing" },
		"wrong submitted reference": func(d *Document) { d.Deliveries[0].Submitted[0].ArtifactOutput = "missing" },
		"invalid digest":            func(d *Document) { d.Artifacts[0].Input.SHA256 = "short" },
		"duplicate artifact":        func(d *Document) { d.Artifacts = append(d.Artifacts, d.Artifacts[0]) },
		"unattempted accepted":      func(d *Document) { d.Deliveries[0].State = "unattempted" },
		"false TLS acceptance":      func(d *Document) { d.Deliveries[0].Transport.TLSObserved = boolptr(false) },
		"secret url": func(d *Document) {
			d.Targets["security"] = Target{Type: "dependency-track", URL: "https://user:password@example.org"}
		},
		"missing end":      func(d *Document) { d.Run.FinishedAt = "" },
		"bad time":         func(d *Document) { d.Run.StartedAt = "yesterday" },
		"empty check pass": func(d *Document) { d.Artifacts[0].Checks.ComponentRequirements = nil },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			d := fixture()
			change(&d)
			if _, e := Marshal(d); e == nil {
				t.Fatal("accepted invalid receipt")
			}
		})
	}
}
func TestParserRefusesUnknownDuplicateTrailingAndOversize(t *testing.T) {
	raw, _ := Marshal(fixture())
	for _, b := range [][]byte{
		[]byte(`{"kind":"rio-run-receipt","kind":"rio-run-receipt"}`),
		bytes.Replace(raw, []byte(`"schemaVersion": 1`), []byte(`"schemaVersion": 1, "archive": "secret"`), 1),
		append(append([]byte{}, raw...), []byte(`{}`)...),
		bytes.Repeat([]byte(" "), MaxBytes+1),
	} {
		if _, e := Parse(b); e == nil {
			t.Fatal("accepted invalid JSON")
		}
	}
}
func TestExplicitLargeValueSummary(t *testing.T) {
	small := SummarizeValue("build-42")
	if small != "build-42" {
		t.Fatalf("small value changed: %#v", small)
	}
	large := SummarizeValue(strings.Repeat("x", MaxValueBytes+1))
	v, ok := large.(ValueSummary)
	if !ok || v.Representation != "sha256-of-json" || len(v.SHA256) != 64 || v.Bytes <= MaxValueBytes {
		t.Fatalf("not explicit: %#v", large)
	}
}
func TestStandardReceiptSizeBudget(t *testing.T) {
	d := fixture()
	b := d.Artifacts[0]
	b.ID = "worker"
	b.Input = &Bytes{Path: "worker.cdx.json", SHA256: strings.Repeat("c", 64), Size: 130}
	d.Artifacts = append(d.Artifacts, b)
	x := d.Deliveries[0]
	x.ArtifactID = "worker"
	x.AttemptID = "attempt-2"
	x.Submitted = []Bytes{{ArtifactOutput: "worker"}}
	d.Deliveries = append(d.Deliveries, x)
	for i := range d.Artifacts {
		d.Artifacts[i].Changes = &Changes{Metadata: []Change{{Field: "build.url", Operation: "add", After: "https://ci.example.org/runs/42", Assertion: "producer", Source: "context-file"}, {Field: "build.id", Operation: "add", After: "42", Assertion: "producer", Source: "context-file"}}}
	}
	raw, e := Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	if len(raw) > 8192 {
		t.Fatalf("%d exceeds budget", len(raw))
	}
}
