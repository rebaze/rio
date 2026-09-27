package receipt

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
)

func TestHTMLRendersStoryAndExactJSONDigestOffline(t *testing.T) {
	d := fixture()
	d.Artifacts[0].Changes = &Changes{Metadata: []Change{{Field: "build.id", Operation: "add", After: "42", Assertion: "producer", Source: "context-file"}}}
	raw, e := Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	// Whitespace is valid but changes the digest of the actual inspected file.
	raw = append(raw, '\n')
	page, e := HTML(raw)
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"api.cdx.json", "build.id", "42", "https://receiver.example.org", "enforced", "200", "11111111-1111-4111-8111-111111111111", delivery.Digest(raw), "Unsigned", "does not prove"} {
		if !bytes.Contains(page, []byte(want)) {
			t.Fatalf("missing %q", want)
		}
	}
	for _, bad := range []string{"<script", "src=", "href=\"http", "@import", "url("} {
		if bytes.Contains(page, []byte(bad)) {
			t.Fatalf("active resource: %s", bad)
		}
	}
	var text bytes.Buffer
	if e := Text(raw, &text); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(text.String(), "unsigned") || !strings.Contains(text.String(), "api.cdx.json") {
		t.Fatal(text.String())
	}
}
func TestHTMLMaliciousTextAndUnknownResponse(t *testing.T) {
	d := fixture()
	d.Artifacts[0].Input.Path = `<script>alert("secret")</script>`
	d.Deliveries[0].State = "unknown"
	d.Deliveries[0].Responses = []Response{{Kind: "unavailable", Value: "unavailable", Code: "transport_unavailable"}}
	d.Run.Outcome = "partial"
	raw, e := Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	page, e := HTML(raw)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(page, []byte("<script>")) || !bytes.Contains(page, []byte("&lt;script&gt;")) || !bytes.Contains(page, []byte("unknown")) || !bytes.Contains(page, []byte("transport_unavailable")) {
		t.Fatal(string(page))
	}
}
func TestReportPublicationNeverOverwrites(t *testing.T) {
	raw, _ := Marshal(fixture())
	page, e := HTML(raw)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "report.html")
	if _, e := PublishReport(path, page); e != nil {
		t.Fatal(e)
	}
	if _, e := PublishReport(path, []byte("replacement")); e == nil {
		t.Fatal("report overwritten")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, page) {
		t.Fatal("report changed")
	}
}
func TestReportRejectsLegacyAndBrokenReceipts(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"schemaVersion":2,"kind":"rio-evidence-record"}`), []byte(`{}`)} {
		if _, e := HTML(raw); e == nil {
			t.Fatal("rendered unsupported document")
		}
	}
}
