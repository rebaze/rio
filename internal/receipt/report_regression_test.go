package receipt

import (
	"bytes"
	"strings"
	"testing"
	"unicode"
)

func TestTextEscapesUntrustedTerminalControls(t *testing.T) {
	const hostile = "visible\x1b[2J\x1b]52;c;YQ==\a\n\r\t\x00\x7f\u009b\u202e\u200b"
	mutations := map[string]func(*Document){
		"version": func(d *Document) { d.RioVersion = hostile },
		"run ID":  func(d *Document) { d.Run.ID = hostile },
		"artifact ID": func(d *Document) {
			d.Artifacts[0].ID = hostile
			d.Deliveries[0].ArtifactID = hostile
			d.Deliveries[0].Intended[0].ArtifactOutput = hostile
			d.Deliveries[0].Submitted[0].ArtifactOutput = hostile
		},
		"input path": func(d *Document) { d.Artifacts[0].Input.Path = hostile },
		"metadata value": func(d *Document) {
			d.Artifacts[0].Changes = &Changes{Metadata: []Change{{Field: "build.id", Operation: "replace", Before: hostile, After: hostile, Assertion: "producer", Source: "context-file"}}}
		},
		"metadata field and source": func(d *Document) {
			d.Artifacts[0].Changes = &Changes{Metadata: []Change{{Field: hostile, Operation: "add", After: "42", Assertion: "producer", Source: hostile}}}
		},
		"specification": func(d *Document) {
			d.Artifacts[0].Changes = &Changes{SpecVersion: &SpecChange{From: hostile, To: hostile}}
		},
		"bulk change": func(d *Document) {
			d.Artifacts[0].Changes = &Changes{Bulk: []BulkChange{{Operation: hostile, Scope: hostile}}}
		},
		"target": func(d *Document) {
			d.Targets[hostile] = d.Targets["security"]
			delete(d.Targets, "security")
			d.Deliveries[0].Target = hostile
		},
		"project": func(d *Document) { d.Deliveries[0].Project = map[string]string{hostile: hostile} },
		"submitted role and media type": func(d *Document) {
			d.Deliveries[0].Submitted[0].Role = hostile
			d.Deliveries[0].Submitted[0].MediaType = hostile
		},
		"response code": func(d *Document) { d.Deliveries[0].Responses[0].Code = hostile },
		"receiver reference": func(d *Document) {
			d.Targets["security"] = Target{Type: "custom", URL: "https://receiver.example.org"}
			d.Deliveries[0].Responses[0].References = []Reference{{Kind: "custom:" + hostile, Value: hostile}}
		},
		"exclusion": func(d *Document) {
			d.Exclusions = []Exclusion{{ArtifactID: hostile, Target: hostile, Reason: hostile, Scope: hostile, Rule: hostile}}
		},
		"exception": func(d *Document) { d.Exceptions = []string{hostile} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			d := fixture()
			mutate(&d)
			raw, err := Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := Text(raw, &out); err != nil {
				t.Fatal(err)
			}
			for _, r := range out.String() {
				if r != '\n' && !unicode.IsPrint(r) {
					t.Fatalf("terminal control %U survived rendering", r)
				}
			}
			if strings.Contains(out.String(), "YQ==\a\n") || !strings.Contains(out.String(), `\u202e\u200b`) {
				t.Fatalf("untrusted value was not visibly escaped: %q", out.String())
			}
			if !strings.Contains(out.String(), "\nrun ") || !strings.Contains(out.String(), "\n\n") {
				t.Fatal("renderer line breaks were escaped")
			}
			if !strings.Contains(out.String(), "visible") {
				t.Fatal("printable text lost")
			}
		})
	}
}

func TestTextEscapingDoesNotChangeJSONOrHTMLValues(t *testing.T) {
	d := fixture()
	d.Artifacts[0].Input.Path = "café\nnext\tline\u202e<script>"
	raw, err := Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Text(raw, &out); err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Artifacts[0].Input.Path != d.Artifacts[0].Input.Path {
		t.Fatal("JSON value changed")
	}
	page, err := HTML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(page, []byte("café\nnext\tline\u202e&lt;script&gt;")) {
		t.Fatal("HTML value changed")
	}
	if !strings.Contains(out.String(), `café\nnext\tline\u202e<script>`) {
		t.Fatal("terminal value is not safely readable")
	}
}

func TestHTMLDistinguishesReconciliationFromConsumedInput(t *testing.T) {
	d := fixture()
	d.Run.Operation = "reconcile"
	d.Run.Stages = map[string]string{"intake": "pre-existing", "delivery": "completed"}
	d.Artifacts = []Artifact{{ID: "api", State: "not-attempted", PreExisting: true}}
	d.Deliveries[0].State = "observed"
	d.Deliveries[0].Intended = nil
	d.Deliveries[0].Submitted = nil
	d.Deliveries[0].Responses = []Response{{Kind: "activity", Value: "not-observed", HTTPStatus: 200}}
	d.Deliveries[0].Prior = &Prior{AttemptID: "original-upload-attempt", SHA256: strings.Repeat("c", 64)}
	d.Run.Prior = &Prior{RunID: "original-upload-run", SHA256: strings.Repeat("d", 64)}
	raw, err := Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	page, err := HTML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(page, []byte("Consumed already-normalized bytes")) {
		t.Fatal("reconcile falsely claims SBOM consumption")
	}
	for _, want := range []string{"No SBOM bytes were consumed", "pre-existing work", "original-upload-attempt", "original-upload-run", strings.Repeat("c", 64), strings.Repeat("d", 64)} {
		if !bytes.Contains(page, []byte(want)) {
			t.Fatalf("missing reconciliation scope %q", want)
		}
	}
	// A native deliver invocation really does consume already-normalized input.
	d = fixture()
	d.Run.Operation = "deliver"
	d.Artifacts[0].PreExisting = true
	d.Artifacts[0].Checks.Mode = "pre-existing"
	raw, err = Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	page, err = HTML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(page, []byte("Consumed already-normalized bytes")) {
		t.Fatal("consumed input scope lost")
	}
}

func TestReportsShowTLSForEachResponse(t *testing.T) {
	d := fixture()
	d.Run.Outcome = "partial"
	d.Deliveries[0].State = "unknown"
	d.Deliveries[0].Responses = []Response{{Kind: "acknowledgment", Value: "unknown", HTTPStatus: 200, TLSObserved: boolptr(true)}, {Kind: "unavailable", Value: "unavailable", Code: "transport_unavailable", TLSObserved: boolptr(false)}}
	raw, err := Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Text(raw, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"acknowledgment=unknown HTTP=200 code= TLS=observed", "unavailable=unavailable HTTP=0 code=transport_unavailable TLS=not observed"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing per-response TLS: %q", want)
		}
	}
	page, err := HTML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(page, []byte("transport_unavailable · TLS not observed")) || !bytes.Contains(page, []byte("HTTP 200 ·  · TLS observed")) {
		t.Fatal("HTML omits per-response TLS")
	}
}
