package sbom_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/rebaze/rio/internal/sbom"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return data
}

func load(t *testing.T, data []byte) *sbom.Document {
	t.Helper()
	doc, err := sbom.Load(data)
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	return doc
}

// tree decodes JSON the way the raw layer does, so comparisons see exactly
// what rio preserved rather than what a lossy decode reconstructed.
func tree(t *testing.T, data []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	return v
}

func TestLoadRejects(t *testing.T) {
	cases := []struct {
		name, input, want string
	}{
		{"not JSON", `{`, "not valid JSON"},
		{"trailing content", `{"bomFormat":"CycloneDX","specVersion":"1.6"}{}`, "trailing content"},
		{"no bomFormat", `{"specVersion":"1.6"}`, `no "bomFormat" field`},
		{"wrong bomFormat", `{"bomFormat":"SPDX","specVersion":"1.6"}`, `bomFormat is "SPDX"`},
		{"no specVersion", `{"bomFormat":"CycloneDX"}`, `no "specVersion" field`},
		{"empty specVersion", `{"bomFormat":"CycloneDX","specVersion":""}`, `no "specVersion" field`},
		{"array not object", `[]`, "not valid JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sbom.Load([]byte(tc.input))
			if err == nil {
				t.Fatalf("Load(%q) = nil, want an error", tc.input)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load(%q) error = %q, want it to contain %q", tc.input, err, tc.want)
			}
		})
	}
}

// The whole pitch of the raw tree is that nothing is lost. Assert it over every
// committed fixture, including the one carrying a construct that a round trip
// through cyclonedx-go's typed model would rewrite (§8, §11 fixture 8).
func TestRoundTripPreservesEveryFixtureExactly(t *testing.T) {
	names, err := filepath.Glob(filepath.Join("..", "..", "testdata", "*.cdx.json"))
	if err != nil || len(names) == 0 {
		t.Fatalf("no fixtures found: %v", err)
	}

	for _, path := range names {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			doc := load(t, data)

			out, err := doc.Bytes()
			if err != nil {
				t.Fatalf("Bytes() = %v", err)
			}
			if diff := cmp.Diff(tree(t, data), tree(t, out)); diff != "" {
				t.Fatalf("round trip changed the document (-input +output):\n%s", diff)
			}
		})
	}
}

// cyclonedx-go injects resolves[].description on encode. rio must not.
func TestRoundTripDoesNotInjectFieldsTheTypedModelWouldAdd(t *testing.T) {
	doc := load(t, fixture(t, "unmodelled-fields.cdx.json"))
	out, err := doc.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte(`"description": ""`)) {
		t.Fatal(`output contains an injected empty "description"; the typed model leaked into the output`)
	}
	if !bytes.Contains(out, []byte("TKSE-4711")) {
		t.Fatal("pedigree patch resolves entry did not survive the round trip")
	}
}

func TestBytesIsDeterministic(t *testing.T) {
	data := fixture(t, "tycho-rcp.cdx.json")

	first, err := load(t, data).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	// A separate Load, not a second Bytes on the same Document: map iteration
	// order differs between runs and must not reach the output (§7).
	second, err := load(t, data).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("two loads of the same bytes serialized differently")
	}
}

// Without UseNumber, integers round trip through float64 and re-serialize as
// 1e+06, corrupting the document (§7).
func TestLargeIntegersSurviveAsWritten(t *testing.T) {
	src := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1000000,
"components":[{"type":"library","name":"a","version":"1","properties":[{"name":"n","value":"v"}]}]}`
	out, err := load(t, []byte(src)).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("1000000")) {
		t.Fatalf("integer was rewritten: %s", out)
	}
	if bytes.Contains(out, []byte("1e+06")) {
		t.Fatalf("integer round tripped through float64: %s", out)
	}
}

// Purl qualifiers are separated by &, which encoding/json escapes to \u0026 by
// default. Valid JSON, but it makes every golden file unreadable and diverges
// from the input bytes for no reason.
func TestPurlAmpersandsAreNotEscaped(t *testing.T) {
	out, err := load(t, fixture(t, "tycho-rcp.cdx.json")).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte(`\u0026`)) {
		t.Fatal("output HTML-escaped a purl qualifier separator")
	}
	if !bytes.Contains(out, []byte("classifier=osgi.bundle&location=")) {
		t.Fatal("expected an unescaped purl qualifier separator in the output")
	}
}

func TestComponentAccessors(t *testing.T) {
	doc := load(t, fixture(t, "tycho-rcp.cdx.json"))

	if got, want := doc.ComponentCount(), 12; got != want {
		t.Fatalf("ComponentCount() = %d, want %d", got, want)
	}
	if doc.Component(-1) != nil || doc.Component(12) != nil {
		t.Fatal("out of range Component() should be nil")
	}
	if got := len(doc.Components()); got != 12 {
		t.Fatalf("len(Components()) = %d, want 12", got)
	}

	c := doc.Component(2)
	if got, want := c.Group(), "p2.eclipse.plugin"; got != want {
		t.Fatalf("Group() = %q, want %q", got, want)
	}
	if got, want := c.Name(), "org.eclipse.core.databinding"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
	if got, want := c.Version(), "1.13.100.v20230708-0916"; got != want {
		t.Fatalf("Version() = %q, want %q", got, want)
	}
	if !strings.HasPrefix(c.PURL(), "pkg:p2/org.eclipse.core.databinding@") {
		t.Fatalf("PURL() = %q", c.PURL())
	}
	if c.BOMRef() != c.PURL() {
		t.Fatalf("BOMRef() = %q, want it to equal the purl in this fixture", c.BOMRef())
	}
}

// A spec version above what cyclonedx-go models must not break anything: the
// typed view is simply unavailable and every accessor falls back to the raw
// tree (§3).
func TestAccessorsFallBackWhenTypedDecodeFails(t *testing.T) {
	doc := load(t, fixture(t, "future-1.9.cdx.json"))

	if doc.TypedDecodeError() == nil {
		t.Fatal("expected the typed decode to fail at spec version 1.9")
	}
	if got, want := doc.SpecVersion(), "1.9"; got != want {
		t.Fatalf("SpecVersion() = %q, want %q", got, want)
	}

	c := doc.Component(0)
	if got, want := c.Name(), "commons-lang3"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
	if got, want := c.Version(), "3.14.0"; got != want {
		t.Fatalf("Version() = %q, want %q", got, want)
	}
	if got, want := c.Group(), "org.apache.commons"; got != want {
		t.Fatalf("Group() = %q, want %q", got, want)
	}
	if !strings.HasPrefix(c.PURL(), "pkg:maven/org.apache.commons/") {
		t.Fatalf("PURL() = %q", c.PURL())
	}

	name, version := doc.Subject()
	if name != "future-client" || version != "5.0.0" {
		t.Fatalf("Subject() = %q, %q", name, version)
	}
}

func TestSubject(t *testing.T) {
	doc := load(t, fixture(t, "plain-maven.cdx.json"))

	name, version := doc.Subject()
	if name != "web" || version != "3.4.1" {
		t.Fatalf("Subject() = %q, %q; want %q, %q", name, version, "web", "3.4.1")
	}

	oldName, oldVersion := doc.SetSubject("rcp-client", "2026.1")
	if oldName != "web" || oldVersion != "3.4.1" {
		t.Fatalf("SetSubject returned %q, %q as the replaced values", oldName, oldVersion)
	}
	name, version = doc.Subject()
	if name != "rcp-client" || version != "2026.1" {
		t.Fatalf("Subject() after override = %q, %q", name, version)
	}
}

func TestSubjectOnDocumentWithoutMetadata(t *testing.T) {
	doc := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`))

	if name, version := doc.Subject(); name != "" || version != "" {
		t.Fatalf("Subject() = %q, %q, want empty", name, version)
	}
	if oldName, oldVersion := doc.SetSubject("a", "1"); oldName != "" || oldVersion != "" {
		t.Fatalf("SetSubject returned %q, %q, want empty", oldName, oldVersion)
	}
	if name, version := doc.Subject(); name != "a" || version != "1" {
		t.Fatalf("Subject() = %q, %q after setting it on a document with no metadata", name, version)
	}
}

func TestFingerprintDetectsMembershipChange(t *testing.T) {
	doc := load(t, fixture(t, "plain-maven.cdx.json"))
	before := doc.Fingerprint()

	if len(before) != 2 {
		t.Fatalf("len(Fingerprint()) = %d, want 2", len(before))
	}
	// Rewriting only the purl, which is all a v1 transform may do, must not
	// move the fingerprint (§6.4).
	doc.Component(0).SetPURL("pkg:maven/org.apache.commons/commons-lang3@3.14.0")
	if diff := cmp.Diff(before, doc.Fingerprint()); diff != "" {
		t.Fatalf("a purl rewrite changed the fingerprint (-before +after):\n%s", diff)
	}
}

func TestPendingPropertiesAreSortedAndAppended(t *testing.T) {
	doc := load(t, fixture(t, "plain-maven.cdx.json"))

	// Deliberately out of order, with one name carrying two values.
	doc.AddMetadataProperty("rebaze:normalize:tool", "rio 0.1.0")
	doc.AddMetadataProperty("rebaze:normalize:repair", "z")
	doc.AddMetadataProperty("rebaze:normalize:artifact-id", "rcp-client")
	doc.AddMetadataProperty("rebaze:normalize:repair", "a")
	doc.Finalize()

	out, err := doc.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Metadata struct {
			Properties []sbom.Property `json:"properties"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}

	got := decoded.Metadata.Properties
	want := []sbom.Property{
		// The generator's own property keeps its position at the front (§7).
		{Name: "maven.goal", Value: "makeBom"},
		{Name: "rebaze:normalize:artifact-id", Value: "rcp-client"},
		{Name: "rebaze:normalize:repair", Value: "a"},
		{Name: "rebaze:normalize:repair", Value: "z"},
		{Name: "rebaze:normalize:tool", Value: "rio 0.1.0"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("metadata.properties (-want +got):\n%s", diff)
	}
}

func TestComponentPropertiesAreSortedAndAppended(t *testing.T) {
	doc := load(t, fixture(t, "tycho-rcp.cdx.json"))

	c := doc.Component(2)
	c.AddProperty("rebaze:normalize:p2-qualifier", "v20230708-0916")
	c.AddProperty("rebaze:normalize:aaa", "first")
	doc.Finalize()

	got := doc.Component(2).Properties()
	want := []sbom.Property{
		{Name: "rebaze:normalize:aaa", Value: "first"},
		{Name: "rebaze:normalize:p2-qualifier", Value: "v20230708-0916"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("component properties (-want +got):\n%s", diff)
	}
}

func TestFinalizeIsIdempotent(t *testing.T) {
	doc := load(t, fixture(t, "plain-maven.cdx.json"))
	doc.AddMetadataProperty("rebaze:normalize:tool", "rio 0.1.0")
	doc.Finalize()
	first, err := doc.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	doc.Finalize()
	second, err := doc.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("a second Finalize changed the document")
	}
}

func TestAddToolExtendsTheShapeAlreadyInUse(t *testing.T) {
	t.Run("flat array stays flat", func(t *testing.T) {
		doc := load(t, fixture(t, "uplift-1.4.cdx.json"))
		doc.AddTool("0.1.0")

		out, err := doc.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Metadata struct {
				Tools json.RawMessage `json:"tools"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(out, &decoded); err != nil {
			t.Fatal(err)
		}
		// The flat array is deprecated at 1.6 but still valid. Uplift changes
		// what is invalid at the target, never what is merely old (§4.3c).
		var tools []map[string]string
		if err := json.Unmarshal(decoded.Metadata.Tools, &tools); err != nil {
			t.Fatalf("metadata.tools is no longer an array: %v", err)
		}
		if len(tools) != 2 {
			t.Fatalf("len(metadata.tools) = %d, want 2", len(tools))
		}
		if tools[0]["name"] != "CycloneDX Maven plugin" {
			t.Fatalf("the generator's tool entry moved or changed: %v", tools[0])
		}
		if tools[1]["name"] != "rio" || tools[1]["version"] != "0.1.0" || tools[1]["vendor"] != "rebaze" {
			t.Fatalf("rio's tool entry = %v", tools[1])
		}
	})

	t.Run("object form is extended in place", func(t *testing.T) {
		doc := load(t, fixture(t, "plain-maven.cdx.json"))
		doc.AddTool("0.1.0")

		out, err := doc.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Metadata struct {
				Tools struct {
					Components []map[string]string `json:"components"`
				} `json:"tools"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(out, &decoded); err != nil {
			t.Fatal(err)
		}
		comps := decoded.Metadata.Tools.Components
		if len(comps) != 2 {
			t.Fatalf("len(metadata.tools.components) = %d, want 2", len(comps))
		}
		if comps[1]["name"] != "rio" || comps[1]["type"] != "application" {
			t.Fatalf("rio's tool component = %v", comps[1])
		}
	})

	t.Run("absent creates the object form at 1.6", func(t *testing.T) {
		doc := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`))
		doc.AddTool("0.1.0")

		out, err := doc.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(out, []byte(`"components"`)) {
			t.Fatalf("expected the object form of metadata.tools: %s", out)
		}
	})

	t.Run("absent creates the array form below 1.5", func(t *testing.T) {
		doc := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`))
		doc.AddTool("0.1.0")

		out, err := doc.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Metadata struct {
				Tools []map[string]string `json:"tools"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(out, &decoded); err != nil {
			t.Fatalf("metadata.tools is not an array at 1.4: %v", err)
		}
		if len(decoded.Metadata.Tools) != 1 {
			t.Fatalf("metadata.tools = %v", decoded.Metadata.Tools)
		}
	})
}

func TestAppendIdentityEvidence(t *testing.T) {
	const value = "rio repair-purl/p2: pkg:p2/com.google.gson@2.8.9.v20220111-1409"

	t.Run("creates the array form", func(t *testing.T) {
		doc := load(t, fixture(t, "plain-maven.cdx.json"))
		doc.Component(0).AppendIdentityEvidence("purl", 0.9, value)

		entries := identityEntries(t, doc, 0)
		if len(entries) != 1 {
			t.Fatalf("len(evidence.identity) = %d, want 1", len(entries))
		}
		if entries[0]["field"] != "purl" {
			t.Fatalf("field = %v", entries[0]["field"])
		}
		if fmt := entries[0]["confidence"]; fmt != json.Number("0.9") {
			t.Fatalf("confidence = %v (%T), want 0.9", fmt, fmt)
		}
		methods, _ := entries[0]["methods"].([]any)
		if len(methods) != 1 {
			t.Fatalf("methods = %v", entries[0]["methods"])
		}
		method := methods[0].(map[string]any)
		if method["technique"] != "other" || method["value"] != value {
			t.Fatalf("method = %v", method)
		}
	})

	t.Run("appends and never overwrites", func(t *testing.T) {
		doc := load(t, fixture(t, "evidence-1.5-object.cdx.json"))
		if _, _, err := doc.Uplift("1.6"); err != nil {
			t.Fatal(err)
		}
		doc.Component(0).AppendIdentityEvidence("purl", 0.9, value)

		entries := identityEntries(t, doc, 0)
		if len(entries) != 2 {
			t.Fatalf("len(evidence.identity) = %d, want 2", len(entries))
		}
		methods := entries[0]["methods"].([]any)
		if methods[0].(map[string]any)["technique"] != "filename" {
			t.Fatalf("the generator's own identity entry was overwritten: %v", entries[0])
		}
		if entries[1]["field"] != "purl" {
			t.Fatalf("rio's entry = %v", entries[1])
		}
	})
}

func identityEntries(t *testing.T, doc *sbom.Document, component int) []map[string]any {
	t.Helper()
	out, err := doc.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.UseNumber()
	var decoded struct {
		Components []struct {
			Evidence struct {
				Identity []map[string]any `json:"identity"`
			} `json:"evidence"`
		} `json:"components"`
	}
	if err := dec.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	return decoded.Components[component].Evidence.Identity
}

// §5 runs the transforms and then the gate over one Document. A second reader
// must see what the first writer wrote: the typed cyclonedx-go view is a
// snapshot of the input and is never refreshed, so reading a mutable field
// through it would hand the gate a purl the document no longer carries.
func TestWritesAreVisibleToTheNextReader(t *testing.T) {
	doc := load(t, fixture(t, "tycho-rcp.cdx.json"))

	c := doc.Component(2)
	if c.Typed() == nil {
		t.Fatal("expected the typed snapshot to be available for this fixture")
	}
	before := c.PURL()

	const repaired = "pkg:maven/org.eclipse.platform/org.eclipse.core.databinding@1.13.100"
	c.SetPURL(repaired)

	// The same view, a freshly fetched view, and the serialized bytes must all
	// agree with the write.
	if got := c.PURL(); got != repaired {
		t.Fatalf("PURL() on the same view = %q, want %q", got, repaired)
	}
	if got := doc.Component(2).PURL(); got != repaired {
		t.Fatalf("PURL() on a fresh view = %q, want %q", got, repaired)
	}
	out, err := doc.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte(repaired)) {
		t.Fatal("the repaired purl is missing from the serialized document")
	}

	// The snapshot itself still holds the input value, which is what makes it
	// unsafe to read for a mutable field.
	if c.Typed().PackageURL != before {
		t.Fatalf("the typed snapshot changed; it is documented as a snapshot of the input")
	}
}

func TestEveryComponentWalksNestedComponents(t *testing.T) {
	doc := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
"components":[
  {"type":"library","name":"outer","version":"1.0","purl":"pkg:maven/g/outer@1.0",
   "components":[{"type":"library","name":"inner","purl":"pkg:maven/g/inner@2.0","version":"2.0"}]},
  {"type":"library","name":"second","version":"3.0"}]}`))

	want := []sbom.ComponentRef{
		{Path: "components[0]", Name: "outer", Version: "1.0", PURL: "pkg:maven/g/outer@1.0"},
		{Path: "components[0].components[0]", Name: "inner", Version: "2.0", PURL: "pkg:maven/g/inner@2.0"},
		{Path: "components[1]", Name: "second", Version: "3.0"},
	}
	if diff := cmp.Diff(want, doc.EveryComponent()); diff != "" {
		t.Fatalf("EveryComponent() (-want +got):\n%s", diff)
	}

	// Components() stays top-level: it is the join key the transform layer
	// addresses by index (§8).
	if got := doc.ComponentCount(); got != 2 {
		t.Fatalf("ComponentCount() = %d, want the two top-level components", got)
	}
}

func TestEveryComponentOnADocumentWithNoComponents(t *testing.T) {
	doc := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`))
	if got := doc.EveryComponent(); len(got) != 0 {
		t.Fatalf("EveryComponent() = %v, want none", got)
	}
}
