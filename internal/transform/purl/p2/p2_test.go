package p2_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/rebaze/rio/internal/sbom"
	"github.com/rebaze/rio/internal/transform"
	"github.com/rebaze/rio/internal/transform/purl/p2"
)

// --- helpers ---------------------------------------------------------------

// component renders one component object. purl is emitted only when non-empty
// so the "no purl at all" case is expressible.
func component(bomRef, group, name, version, purl, extra string) string {
	var b strings.Builder
	b.WriteString(`{"type":"library","bom-ref":`)
	b.WriteString(quote(bomRef))
	if group != "" {
		b.WriteString(`,"group":` + quote(group))
	}
	b.WriteString(`,"name":` + quote(name))
	b.WriteString(`,"version":` + quote(version))
	if purl != "" {
		b.WriteString(`,"purl":` + quote(purl))
	}
	if extra != "" {
		b.WriteString("," + extra)
	}
	b.WriteString("}")
	return b.String()
}

func quote(s string) string {
	out, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(out)
}

func source(components ...string) []byte {
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,` +
		`"metadata":{"component":{"type":"application","name":"demo","version":"1.0.0"}},` +
		`"components":[` + strings.Join(components, ",") + `]}`)
}

func load(t *testing.T, src []byte) *sbom.Document {
	t.Helper()
	doc, err := sbom.Load(src)
	if err != nil {
		t.Fatalf("sbom.Load: %v", err)
	}
	return doc
}

func newTransform(t *testing.T, cfg transform.Config, baseDir string) transform.Transform {
	t.Helper()
	tr, err := p2.New(cfg, baseDir)
	if err != nil {
		t.Fatalf("p2.New(%v): %v", cfg, err)
	}
	return tr
}

// run applies the transform with the default configuration and returns the
// result plus the resulting purl of every component, in document order.
func run(t *testing.T, cfg transform.Config, src []byte) (transform.Result, []string, *sbom.Document) {
	t.Helper()
	doc := load(t, src)
	if cfg == nil {
		cfg = transform.Config{"ecosystem": "p2"}
	}
	res, err := newTransform(t, cfg, t.TempDir()).Apply(doc)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return res, purlsOf(t, doc), doc
}

// purlsOf reads every component purl back out of the serialized document,
// which is what ships. sbom.Component.PURL reads the typed view and so does not
// observe writes the transform made to the raw tree.
func purlsOf(t *testing.T, doc *sbom.Document) []string {
	t.Helper()
	var tree struct {
		Components []struct {
			PURL string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(serialize(t, doc), &tree); err != nil {
		t.Fatalf("re-decoding output: %v", err)
	}
	out := make([]string, 0, len(tree.Components))
	for _, c := range tree.Components {
		out = append(out, c.PURL)
	}
	return out
}

// serialize finalizes and encodes the document. Finalize is idempotent, so
// several helpers may each call it.
func serialize(t *testing.T, doc *sbom.Document) []byte {
	t.Helper()
	doc.Finalize()
	out, err := doc.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	return out
}

// bundle is a well-formed mapping candidate: p2 purl, osgi.bundle classifier,
// group under the p2. prefix.
func bundle(name, version, extraQualifiers, extra string) string {
	purl := "pkg:p2/" + name + "@" + version + "?classifier=osgi.bundle" + extraQualifiers
	return component(purl, "p2.eclipse.plugin", name, version, purl, extra)
}

func properties(pairs ...string) string {
	entries := make([]string, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		entries = append(entries, `{"name":`+quote(pairs[i])+`,"value":`+quote(pairs[i+1])+`}`)
	}
	return `"properties":[` + strings.Join(entries, ",") + `]`
}

func onlyNote(t *testing.T, res transform.Result) transform.Note {
	t.Helper()
	if len(res.Notes) != 1 {
		t.Fatalf("want exactly 1 note, got %d: %+v", len(res.Notes), res.Notes)
	}
	return res.Notes[0]
}

// componentProperties returns the properties of component i as written to the
// serialized document.
func componentProperties(t *testing.T, doc *sbom.Document, i int) map[string]string {
	t.Helper()
	var tree struct {
		Components []struct {
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(serialize(t, doc), &tree); err != nil {
		t.Fatalf("re-decoding output: %v", err)
	}
	props := map[string]string{}
	for _, p := range tree.Components[i].Properties {
		props[p.Name] = p.Value
	}
	return props
}

// --- 6.1 version qualifier -------------------------------------------------

func TestVersionQualifier(t *testing.T) {
	// com.example.unmapped is deliberately absent from the built-in table, so
	// only the version rule can fire here.
	cases := []struct {
		name          string
		version       string
		wantVersion   string
		wantQualifier string
	}{
		{"eclipse build qualifier", "2.8.9.v20220111-1409", "2.8.9", "v20220111-1409"},
		{"non-numeric qualifier on a snapshot", "1.0.0.today", "1.0.0", "today"},
		{"four numeric segments are a real maven version", "1.2.3.4", "1.2.3.4", ""},
		{"three segments", "1.2.3", "1.2.3", ""},
		{"five segments", "1.2.3.4.5", "1.2.3.4.5", ""},
		{"empty fourth segment is not a qualifier", "1.2.3.", "1.2.3.", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := source(bundle("com.example.unmapped", tc.version, "", ""))
			res, purls, doc := run(t, nil, src)

			want := "pkg:p2/com.example.unmapped@" + tc.wantVersion + "?classifier=osgi.bundle"
			if purls[0] != want {
				t.Errorf("purl = %q, want %q", purls[0], want)
			}

			props := componentProperties(t, doc, 0)
			got, present := props[p2.QualifierProperty]
			if tc.wantQualifier == "" {
				if present {
					t.Errorf("qualifier property written as %q, want none", got)
				}
			} else {
				if got != tc.wantQualifier {
					t.Errorf("rebaze:normalize:p2-qualifier = %q (present=%v), want %q", got, present, tc.wantQualifier)
				}
			}

			// A version fix is a Change even though the component stays unmapped.
			wantChanges := 0
			if tc.wantQualifier != "" {
				wantChanges = 1
			}
			if len(res.Changes) != wantChanges {
				t.Fatalf("want %d changes, got %d: %+v", wantChanges, len(res.Changes), res.Changes)
			}
			if wantChanges == 1 {
				ch := res.Changes[0]
				if ch.ComponentIndex != 0 || ch.Field != "purl" {
					t.Errorf("change = %+v, want index 0 field purl", ch)
				}
				if ch.From != "pkg:p2/com.example.unmapped@"+tc.version+"?classifier=osgi.bundle" {
					t.Errorf("change.From = %q", ch.From)
				}
				if ch.To != want {
					t.Errorf("change.To = %q, want %q", ch.To, want)
				}
			}
		})
	}
}

// --- 6.2 resolution order --------------------------------------------------

func TestMappingFromPURLQualifiersBeatsTable(t *testing.T) {
	// com.google.gson IS in the built-in table; the qualifiers must win (step 1).
	src := source(bundle("com.google.gson", "2.8.9.v20220111-1409",
		"&maven-groupId=q.group&maven-artifactId=q-artifact", ""))
	res, purls, _ := run(t, nil, src)

	if want := "pkg:maven/q.group/q-artifact@2.8.9"; purls[0] != want {
		t.Errorf("purl = %q, want %q", purls[0], want)
	}
	if len(res.Notes) != 0 {
		t.Errorf("want no notes, got %+v", res.Notes)
	}
	if len(res.Changes) != 1 {
		t.Fatalf("want exactly one change, got %+v", res.Changes)
	}
}

func TestMappingFromComponentPropertiesBeatsTable(t *testing.T) {
	cases := []struct{ name, groupKey, artifactKey string }{
		{"hyphen keys", "maven-groupId", "maven-artifactId"},
		{"dotted keys", "maven.groupId", "maven.artifactId"},
		{"cdx keys", "cdx:maven:groupId", "cdx:maven:artifactId"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := source(bundle("com.google.gson", "2.8.9.v20220111-1409", "",
				properties(tc.groupKey, "p.group", tc.artifactKey, "p-artifact")))
			res, purls, _ := run(t, nil, src)

			if want := "pkg:maven/p.group/p-artifact@2.8.9"; purls[0] != want {
				t.Errorf("purl = %q, want %q", purls[0], want)
			}
			if len(res.Notes) != 0 {
				t.Errorf("want no notes, got %+v", res.Notes)
			}
		})
	}
}

func TestComponentPropertyPairsAreCheckedInOrder(t *testing.T) {
	src := source(bundle("com.google.gson", "2.8.9.v20220111-1409", "",
		properties(
			"cdx:maven:groupId", "third.group", "cdx:maven:artifactId", "third-artifact",
			"maven-groupId", "first.group", "maven-artifactId", "first-artifact")))
	_, purls, _ := run(t, nil, src)

	if want := "pkg:maven/first.group/first-artifact@2.8.9"; purls[0] != want {
		t.Errorf("purl = %q, want %q", purls[0], want)
	}
}

func TestHalfAPropertyPairIsNotAHit(t *testing.T) {
	// Only the groupId half is present, so the table must still win.
	src := source(bundle("com.google.gson", "2.8.9.v20220111-1409", "",
		properties("maven-groupId", "p.group")))
	_, purls, _ := run(t, nil, src)

	if want := "pkg:maven/com.google.code.gson/gson@2.8.9"; purls[0] != want {
		t.Errorf("purl = %q, want %q", purls[0], want)
	}
}

func TestMappingFromTable(t *testing.T) {
	cases := []struct{ bsn, want string }{
		{"com.google.gson", "pkg:maven/com.google.code.gson/gson@2.8.9"},
		{"org.apache.commons.lang3", "pkg:maven/org.apache.commons/commons-lang3@2.8.9"},
		{"org.eclipse.osgi", "pkg:maven/org.eclipse.platform/org.eclipse.osgi@2.8.9"},
	}
	for _, tc := range cases {
		t.Run(tc.bsn, func(t *testing.T) {
			src := source(bundle(tc.bsn, "2.8.9.v20220111-1409",
				"&location=https%3A%2F%2Fdownload.eclipse.org%2Freleases%2F2023-12%2F", ""))
			res, purls, _ := run(t, nil, src)

			if purls[0] != tc.want {
				t.Errorf("purl = %q, want %q", purls[0], tc.want)
			}
			// The p2 qualifiers describe the p2 repository, not the maven artifact.
			if strings.Contains(purls[0], "classifier=") || strings.Contains(purls[0], "location=") {
				t.Errorf("p2 qualifiers survived into %q", purls[0])
			}
			if len(res.Notes) != 0 {
				t.Errorf("want no notes, got %+v", res.Notes)
			}
		})
	}
}

func TestBuiltInTableHasExactlyTheSeededEntries(t *testing.T) {
	// The launcher fragment must stay absent: the real fixture needs it to
	// exercise the unmapped path.
	for _, bsn := range []string{"org.eclipse.equinox.launcher.gtk.linux.x86_64"} {
		src := source(bundle(bsn, "1.2.800.v20231003-1442", "", ""))
		res, purls, _ := run(t, nil, src)
		if !strings.HasPrefix(purls[0], "pkg:p2/") {
			t.Errorf("%s mapped to %q, want it left unmapped", bsn, purls[0])
		}
		if n := onlyNote(t, res); n.Kind != transform.NoteUnmapped {
			t.Errorf("%s note kind = %q, want unmapped", bsn, n.Kind)
		}
	}
	for _, bsn := range []string{
		"org.eclipse.osgi",
		"org.eclipse.equinox.common",
		"org.eclipse.equinox.launcher",
		"org.eclipse.core.databinding",
		"org.eclipse.core.databinding.beans",
		"org.eclipse.core.databinding.observable",
		"org.eclipse.core.databinding.property",
		"org.apache.commons.lang3",
		"com.google.gson",
	} {
		src := source(bundle(bsn, "1.0.0.v1", "", ""))
		_, purls, _ := run(t, nil, src)
		if !strings.HasPrefix(purls[0], "pkg:maven/") {
			t.Errorf("%s = %q, want a maven purl from the built-in table", bsn, purls[0])
		}
	}
}

// --- unmapped --------------------------------------------------------------

func TestUnknownBundleStaysP2AndInfersNothing(t *testing.T) {
	src := source(bundle("com.example.foo", "1.0.0.v20240101",
		"&location=https%3A%2F%2Fwww.example.p2.repo%2F", ""))
	res, purls, _ := run(t, nil, src)

	got := purls[0]
	if !strings.HasPrefix(got, "pkg:p2/com.example.foo@") {
		t.Errorf("purl = %q, want the p2 type and name kept", got)
	}
	// Never infer a groupId from a symbolic name prefix.
	if strings.Contains(got, "pkg:maven") || strings.Contains(got, "com.example/foo") {
		t.Fatalf("a groupId was inferred from the symbolic name: %q", got)
	}
	// The version fix still applies, and the p2 qualifiers survive BYTE FOR
	// BYTE. Rebuilding through packageurl-go would re-emit the location value
	// canonically, as "https:%2F%2F..." rather than the generator's
	// "https%3A%2F%2F...": an equal value but a different string, and the
	// component's bom-ref still holds the original spelling (§6.4).
	want := "pkg:p2/com.example.foo@1.0.0?classifier=osgi.bundle&location=https%3A%2F%2Fwww.example.p2.repo%2F"
	if got != want {
		t.Errorf("purl = %q, want %q", got, want)
	}
	if len(res.Changes) != 1 {
		t.Errorf("want the version fix reported as a change, got %+v", res.Changes)
	}

	n := onlyNote(t, res)
	if n.Kind != transform.NoteUnmapped {
		t.Errorf("note kind = %q, want %q", n.Kind, transform.NoteUnmapped)
	}
	if n.Reason != "no mapping entry" {
		t.Errorf("note reason = %q, want %q", n.Reason, "no mapping entry")
	}
	if n.ComponentIndex != 0 {
		t.Errorf("note index = %d, want 0", n.ComponentIndex)
	}
	if n.PURL != "pkg:p2/com.example.foo@1.0.0.v20240101?classifier=osgi.bundle&location=https%3A%2F%2Fwww.example.p2.repo%2F" {
		t.Errorf("note purl = %q, want the purl as found", n.PURL)
	}
}

// --- 6.2 scope filter / 6.3 never overwrite a valid non-p2 purl ------------

func TestSkipped(t *testing.T) {
	mavenPURL := "pkg:maven/p2.p2.installable.unit/org.eclipse.equinox.executable_root.gtk.linux.x86_64@3.8.2300.v20231106-1826?type=p2-installable-unit"
	featurePURL := "pkg:p2/org.eclipse.equinox.executable@3.8.2300.v20231106-1826?classifier=org.eclipse.update.feature"
	reactorPURL := "pkg:p2/example.plugin@1.0.0.today?classifier=osgi.bundle"

	cases := []struct {
		name       string
		component  string
		wantPURL   string
		wantReason string
	}{
		{
			// A valid pkg:maven purl with a synthetic groupId that will never
			// resolve. Garbage in stays garbage, visibly (§6.3).
			name:      "non-p2 purl is left alone unconditionally",
			component: component(mavenPURL, "p2.p2.installable.unit", "org.eclipse.equinox.executable_root.gtk.linux.x86_64", "3.8.2300.v20231106-1826", mavenPURL, ""),
			wantPURL:  mavenPURL,
		},
		{
			// No name to resolve it by, so §6.3's second case cannot apply.
			name:      "no purl and no name",
			component: component("nameless", "p2.eclipse.plugin", "", "1.0.0.v1", "", ""),
			wantPURL:  "",
		},
		{
			name:      "no purl and a group outside the p2. prefix",
			component: component("nothing", "tycho-demo", "nothing", "1.0.0.v1", "", ""),
			wantPURL:  "",
		},
		{
			name:      "feature classifier",
			component: component(featurePURL, "p2.eclipse.feature", "org.eclipse.equinox.executable", "3.8.2300.v20231106-1826", featurePURL, ""),
		},
		{
			name:      "group outside the p2. prefix",
			component: component(reactorPURL, "tycho-demo", "example.plugin", "1.0.0-SNAPSHOT", reactorPURL, ""),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, purls, _ := run(t, nil, source(tc.component))
			if tc.wantPURL != "" && purls[0] != tc.wantPURL {
				t.Errorf("purl = %q, want it untouched at %q", purls[0], tc.wantPURL)
			}
			n := onlyNote(t, res)
			if n.Kind != transform.NoteSkipped {
				t.Errorf("note kind = %q, want %q", n.Kind, transform.NoteSkipped)
			}
			if n.Reason == "" {
				t.Error("skipped note carries no reason")
			}
		})
	}
}

func TestNonP2PURLIsNeverRewritten(t *testing.T) {
	// Even when its bundle symbolic name is in the table.
	mavenPURL := "pkg:maven/whatever/com.google.gson@2.8.9.v20220111-1409"
	src := source(component(mavenPURL, "p2.eclipse.plugin", "com.google.gson", "2.8.9.v20220111-1409", mavenPURL, ""))
	res, purls, doc := run(t, nil, src)

	if purls[0] != mavenPURL {
		t.Errorf("purl = %q, want %q", purls[0], mavenPURL)
	}
	if len(res.Changes) != 0 {
		t.Errorf("want no changes, got %+v", res.Changes)
	}
	if props := componentProperties(t, doc, 0); len(props) != 0 {
		t.Errorf("want no properties written, got %v", props)
	}
}

// --- configuration ---------------------------------------------------------

func TestConfigurableGroupPrefixAndClassifier(t *testing.T) {
	purl := "pkg:p2/com.google.gson@2.8.9.v20220111-1409?classifier=bundle"
	src := source(component(purl, "acme.plugins", "com.google.gson", "2.8.9", purl, ""))

	// Defaults do not match this shape.
	res, purls, _ := run(t, nil, src)
	if !strings.HasPrefix(purls[0], "pkg:p2/") {
		t.Errorf("with default config purl = %q, want it skipped", purls[0])
	}
	if n := onlyNote(t, res); n.Kind != transform.NoteSkipped {
		t.Errorf("with default config note kind = %q, want skipped", n.Kind)
	}

	cfg := transform.Config{"ecosystem": "p2", "groupPrefix": "acme.", "classifier": "bundle"}
	res, purls, _ = run(t, cfg, src)
	if want := "pkg:maven/com.google.code.gson/gson@2.8.9"; purls[0] != want {
		t.Errorf("purl = %q, want %q", purls[0], want)
	}
	if len(res.Notes) != 0 {
		t.Errorf("want no notes, got %+v", res.Notes)
	}
}

func TestTableOverrideMergesOverTheBuiltIn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mappings", "p2-maven.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	table := `{"schemaVersion":1,"entries":{
		"com.google.gson":{"groupId":"override.group","artifactId":"override-artifact"},
		"com.example.added":{"groupId":"added.group","artifactId":"added-artifact"}}}`
	if err := os.WriteFile(path, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := transform.Config{"ecosystem": "p2", "table": "mappings/p2-maven.json"}
	tr, err := p2.New(cfg, dir)
	if err != nil {
		t.Fatalf("p2.New: %v", err)
	}
	doc := load(t, source(
		bundle("com.google.gson", "2.8.9.v20220111-1409", "", ""),
		bundle("com.example.added", "1.0.0.v1", "", ""),
		bundle("org.apache.commons.lang3", "3.12.0.v20210515-1504", "", ""),
	))
	if _, err := tr.Apply(doc); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	want := []string{
		"pkg:maven/override.group/override-artifact@2.8.9",  // overridden
		"pkg:maven/added.group/added-artifact@1.0.0",        // added
		"pkg:maven/org.apache.commons/commons-lang3@3.12.0", // still built in
	}
	for i, got := range purlsOf(t, doc) {
		if got != want[i] {
			t.Errorf("component %d purl = %q, want %q", i, got, want[i])
		}
	}
}

func TestTableConfigErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return name
	}

	cases := []struct{ name, table, wantSubstring string }{
		{"missing file", "absent.json", "absent.json"},
		{"bad json", write("bad.json", "{"), "bad.json"},
		{"wrong schema version", write("v2.json", `{"schemaVersion":2,"entries":{}}`), "schemaVersion"},
		{"empty groupId", write("nogroup.json", `{"schemaVersion":1,"entries":{"a.b":{"groupId":"","artifactId":"x"}}}`), "a.b"},
		{"empty artifactId", write("noartifact.json", `{"schemaVersion":1,"entries":{"a.b":{"groupId":"x","artifactId":""}}}`), "a.b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p2.New(transform.Config{"ecosystem": "p2", "table": tc.table}, dir)
			if err == nil {
				t.Fatalf("want an error naming %q", tc.wantSubstring)
			}
			if !strings.Contains(err.Error(), tc.wantSubstring) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantSubstring)
			}
		})
	}
}

func TestUnknownConfigKeyIsRejected(t *testing.T) {
	_, err := p2.New(transform.Config{"ecosystem": "p2", "tabel": "x.json"}, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "tabel") {
		t.Fatalf("err = %v, want it to name the unknown key", err)
	}
}

func TestID(t *testing.T) {
	if got := newTransform(t, transform.Config{"ecosystem": "p2"}, t.TempDir()).ID(); got != "repair-purl/p2" {
		t.Errorf("ID() = %q, want %q", got, "repair-purl/p2")
	}
	if p2.ID != "repair-purl/p2" {
		t.Errorf("p2.ID = %q", p2.ID)
	}
}

// --- 6.4 what the transform is allowed to write ----------------------------

func TestOnlyPURLAndPropertiesChange(t *testing.T) {
	src := source(
		bundle("com.google.gson", "2.8.9.v20220111-1409",
			"&location=https%3A%2F%2Fdownload.eclipse.org%2Freleases%2F2023-12%2F", ""),
		bundle("com.example.foo", "1.0.0.v20240101", "", ""),
		component("pkg:p2/example.feature@1.0.0.today?classifier=org.eclipse.update.feature",
			"p2.eclipse.feature", "example.feature", "1.0.0-SNAPSHOT",
			"pkg:p2/example.feature@1.0.0.today?classifier=org.eclipse.update.feature", ""),
		component("pkg:maven/tycho-demo/example@1.0.0-SNAPSHOT?type=eclipse-repository",
			"tycho-demo", "example", "1.0.0-SNAPSHOT",
			"pkg:maven/tycho-demo/example@1.0.0-SNAPSHOT?type=eclipse-repository", ""),
	)

	doc := load(t, src)
	if _, err := newTransform(t, nil, t.TempDir()).Apply(doc); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	out := serialize(t, doc)

	before := decode(t, src)
	after := decode(t, out)

	beforeComps := comps(t, before)
	afterComps := comps(t, after)
	if len(beforeComps) != len(afterComps) {
		t.Fatalf("component count %d -> %d", len(beforeComps), len(afterComps))
	}

	// bom-ref, name, group and version must be byte identical (§6.4). Diff the
	// whole component tree, ignoring only what the transform is allowed to write.
	for i := range beforeComps {
		a := without(beforeComps[i], "purl", "properties")
		b := without(afterComps[i], "purl", "properties")
		if diff := cmp.Diff(a, b); diff != "" {
			t.Errorf("component %d changed outside purl/properties (-in +out):\n%s", i, diff)
		}
	}

	// Order is preserved, identified by bom-ref.
	for i := range beforeComps {
		if beforeComps[i]["bom-ref"] != afterComps[i]["bom-ref"] {
			t.Errorf("component %d bom-ref %v -> %v", i, beforeComps[i]["bom-ref"], afterComps[i]["bom-ref"])
		}
	}

	// The transform writes no metadata and no evidence: the pipeline does that
	// from the returned Changes and Notes.
	if diff := cmp.Diff(before["metadata"], after["metadata"]); diff != "" {
		t.Errorf("metadata changed (-in +out):\n%s", diff)
	}
	if bytes.Contains(out, []byte(`"evidence"`)) {
		t.Error("the transform wrote evidence.identity; that is the pipeline's job")
	}
	if bytes.Contains(out, []byte("rebaze:normalize:repair")) ||
		bytes.Contains(out, []byte("rebaze:normalize:unmapped")) {
		t.Error("the transform wrote repair records; that is the pipeline's job")
	}
}

func TestDeterministicAcrossRuns(t *testing.T) {
	src := source(
		bundle("com.google.gson", "2.8.9.v20220111-1409", "", ""),
		bundle("com.example.foo", "1.0.0.v20240101", "", ""),
		bundle("org.eclipse.osgi", "3.18.600.v20231110-1900", "", ""),
	)
	var first []byte
	var firstRes transform.Result
	for i := 0; i < 5; i++ {
		doc := load(t, src)
		res, err := newTransform(t, nil, t.TempDir()).Apply(doc)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		out := serialize(t, doc)
		if i == 0 {
			first, firstRes = out, res
			continue
		}
		if !bytes.Equal(first, out) {
			t.Fatalf("run %d differs from run 0", i)
		}
		if diff := cmp.Diff(firstRes, res); diff != "" {
			t.Fatalf("run %d result differs from run 0:\n%s", i, diff)
		}
	}
}

func decode(t *testing.T, data []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	return out
}

func comps(t *testing.T, tree map[string]any) []map[string]any {
	t.Helper()
	list, ok := tree["components"].([]any)
	if !ok {
		t.Fatal("no components array")
	}
	out := make([]map[string]any, 0, len(list))
	for _, entry := range list {
		obj, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("component is %T, want an object", entry)
		}
		out = append(out, obj)
	}
	return out
}

func without(obj map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for k, v := range obj {
		out[k] = v
	}
	for _, k := range keys {
		delete(out, k)
	}
	return out
}

// TestScopeFilterGatesBothOperations pins the reading of §6 that the scope
// filter in §6.2 gates the whole transform, not only the coordinate mapping.
// §6.2 says a filtered-out component is "neither repaired nor counted as
// unmapped", and stripping the Eclipse qualifier is a repair: turning a
// first-party 1.0.0.today into 1.0.0 would make an unreleased reactor module
// read as a released one, which is the confident-looking lie the scope filter
// exists to prevent.
func TestScopeFilterGatesBothOperations(t *testing.T) {
	featurePURL := "pkg:p2/example.feature@1.0.0.today?classifier=org.eclipse.update.feature"
	reactorPURL := "pkg:p2/example.plugin@1.0.0.today?classifier=osgi.bundle"

	cases := []struct {
		name      string
		purl      string
		component string
	}{
		{"skipped on classifier", featurePURL,
			component(featurePURL, "p2.eclipse.feature", "example.feature", "1.0.0-SNAPSHOT", featurePURL, "")},
		{"skipped on group", reactorPURL,
			component(reactorPURL, "tycho-demo", "example.plugin", "1.0.0-SNAPSHOT", reactorPURL, "")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, purls, doc := run(t, nil, source(tc.component))

			if purls[0] != tc.purl {
				t.Errorf("purl = %q, want it untouched at %q", purls[0], tc.purl)
			}
			if got := componentProperties(t, doc, 0)[p2.QualifierProperty]; got != "" {
				t.Errorf("rebaze:normalize:p2-qualifier = %q, want nothing written on a skipped component", got)
			}
			if len(res.Changes) != 0 {
				t.Errorf("want no change on a skipped component, got %+v", res.Changes)
			}
			// Skipped is a third outcome, counted separately from unmapped so
			// that out of scope never reads as a miss (§6.2).
			if n := onlyNote(t, res); n.Kind != transform.NoteSkipped {
				t.Errorf("note kind = %q, want %q", n.Kind, transform.NoteSkipped)
			}
		})
	}
}

// An in-scope bundle that the table does not know still gets its version fixed:
// the two operations are independent and either can succeed without the other
// (§6). This is the counterpart to TestScopeFilterGatesBothOperations.
func TestVersionFixSurvivesAFailedMapping(t *testing.T) {
	purl := "pkg:p2/org.eclipse.equinox.launcher.gtk.linux.x86_64@1.2.800.v20231003-1442?classifier=osgi.bundle"
	res, purls, doc := run(t, nil, source(component(purl, "p2.eclipse.plugin",
		"org.eclipse.equinox.launcher.gtk.linux.x86_64", "1.2.800.v20231003-1442", purl, "")))

	want := "pkg:p2/org.eclipse.equinox.launcher.gtk.linux.x86_64@1.2.800?classifier=osgi.bundle"
	if purls[0] != want {
		t.Errorf("purl = %q, want %q", purls[0], want)
	}
	if got := componentProperties(t, doc, 0)[p2.QualifierProperty]; got != "v20231003-1442" {
		t.Errorf("rebaze:normalize:p2-qualifier = %q, want %q", got, "v20231003-1442")
	}
	if len(res.Changes) != 1 {
		t.Fatalf("want the version fix reported as a change, got %+v", res.Changes)
	}
	if n := onlyNote(t, res); n.Kind != transform.NoteUnmapped {
		t.Errorf("note kind = %q, want %q", n.Kind, transform.NoteUnmapped)
	}
}

// TestComponentVersionIsNeverTouched covers the divergence §6.4 calls
// intentional: the purl version is the lookup key and gets repaired, while
// component.version is what the generator asserted and stays as found.
func TestComponentVersionIsNeverTouched(t *testing.T) {
	purl := "pkg:p2/com.google.gson@2.8.9.v20220111-1409?classifier=osgi.bundle"
	src := source(component(purl, "p2.eclipse.plugin", "com.google.gson", "2.8.9-SNAPSHOT", purl, ""))
	_, purls, doc := run(t, nil, src)

	if want := "pkg:maven/com.google.code.gson/gson@2.8.9"; purls[0] != want {
		t.Fatalf("purl = %q, want %q", purls[0], want)
	}
	after := comps(t, decode(t, serialize(t, doc)))
	if got := after[0]["version"]; got != "2.8.9-SNAPSHOT" {
		t.Errorf("component.version = %v, want it left at 2.8.9-SNAPSHOT", got)
	}
	if got := after[0]["bom-ref"]; got != purl {
		t.Errorf("bom-ref = %v, want it left at the original purl", got)
	}
	if got := after[0]["name"]; got != "com.google.gson" {
		t.Errorf("name = %v, want it untouched", got)
	}
	if got := after[0]["group"]; got != "p2.eclipse.plugin" {
		t.Errorf("group = %v, want it untouched", got)
	}
}

// §6.3: "The transform only touches components whose purl type is p2, or whose
// purl is absent but which carry an OSGi bundle symbolic name."
//
// There is no classifier qualifier to check on a component with no purl, so
// the scope filter is the group prefix plus a symbolic name, and a coordinate
// is only ever written on a real table or property hit. Nothing is inferred
// from the name.
func TestComponentWithNoPURLIsResolvedByItsSymbolicName(t *testing.T) {
	t.Run("a table hit writes the coordinate and strips the qualifier", func(t *testing.T) {
		res, purls, doc := run(t, nil, source(component(
			"ref", "p2.eclipse.plugin", "org.eclipse.osgi", "3.18.600.v20231110-1900", "", "")))

		want := "pkg:maven/org.eclipse.platform/org.eclipse.osgi@3.18.600"
		if purls[0] != want {
			t.Fatalf("purl = %q, want %q", purls[0], want)
		}
		if got := componentProperties(t, doc, 0)[p2.QualifierProperty]; got != "v20231110-1900" {
			t.Fatalf("%s = %q, want %q", p2.QualifierProperty, got, "v20231110-1900")
		}
		if len(res.Changes) != 1 {
			t.Fatalf("Changes = %+v, want one", res.Changes)
		}
		// There was no purl, so the repair record's from= is empty. That is
		// the honest reading: nothing was replaced, a coordinate was supplied.
		if res.Changes[0].From != "" || res.Changes[0].To != want {
			t.Fatalf("Change = %+v", res.Changes[0])
		}
		if len(res.Notes) != 0 {
			t.Fatalf("Notes = %+v, want none", res.Notes)
		}
	})

	t.Run("component properties resolve it too", func(t *testing.T) {
		_, purls, _ := run(t, nil, source(component(
			"ref", "p2.eclipse.plugin", "com.example.widget", "2.0.0", "",
			properties("maven-groupId", "com.example", "maven-artifactId", "widget"))))

		if want := "pkg:maven/com.example/widget@2.0.0"; purls[0] != want {
			t.Fatalf("purl = %q, want %q", purls[0], want)
		}
	})

	t.Run("no hit writes nothing and is reported unmapped", func(t *testing.T) {
		res, purls, doc := run(t, nil, source(component(
			"ref", "p2.eclipse.plugin", "com.example.foo", "1.0.0.v1", "", "")))

		if purls[0] != "" {
			t.Fatalf("purl = %q, want it left absent: a groupId is never inferred from a name", purls[0])
		}
		if got := componentProperties(t, doc, 0)[p2.QualifierProperty]; got != "" {
			t.Fatalf("%s = %q, want nothing written when no coordinate was found", p2.QualifierProperty, got)
		}
		if len(res.Changes) != 0 {
			t.Fatalf("Changes = %+v, want none", res.Changes)
		}
		if n := onlyNote(t, res); n.Kind != transform.NoteUnmapped {
			t.Fatalf("note kind = %q, want %q", n.Kind, transform.NoteUnmapped)
		}
	})
}

// packageurl-go only refuses an empty name, so a groupId carrying a separator
// silently becomes a nested namespace that looks plausible and resolves to
// nothing. Steps 1 and 2 of §6.2 read these out of the SBOM.
func TestResolvedCoordinatesAreValidated(t *testing.T) {
	cases := []struct {
		name, group, artifact, wantReason string
	}{
		{"a slash in the groupId", "com/example", "widget", "contains a purl separator"},
		{"an at sign in the artifactId", "com.example", "widget@1", "contains a purl separator"},
		{"whitespace in the groupId", "com example", "widget", "contains whitespace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			purl := "pkg:p2/com.example.widget@2.0.0?classifier=osgi.bundle"
			res, purls, _ := run(t, nil, source(component(
				purl, "p2.eclipse.plugin", "com.example.widget", "2.0.0", purl,
				properties("maven-groupId", tc.group, "maven-artifactId", tc.artifact))))

			if strings.HasPrefix(purls[0], "pkg:maven/") {
				t.Fatalf("purl = %q, want the bad coordinate refused", purls[0])
			}
			n := onlyNote(t, res)
			if n.Kind != transform.NoteUnmapped {
				t.Fatalf("note kind = %q, want %q", n.Kind, transform.NoteUnmapped)
			}
			if !strings.Contains(n.Reason, tc.wantReason) {
				t.Fatalf("reason = %q, want it to mention %q", n.Reason, tc.wantReason)
			}
		})
	}
}

// §6.1 is applied once, to the raw version substring, with the decoded form
// derived from that same split. Applying it separately to the decoded version
// disagrees when the version carries percent-encoding — %2E is a dot after
// decoding but not before — and the document would then claim a qualifier drop
// that did not happen.
func TestVersionRuleIsAppliedOnceToTheRawVersion(t *testing.T) {
	purl := "pkg:p2/com.google.gson@1.0.0%2E5.v1?classifier=osgi.bundle"
	_, purls, doc := run(t, nil, source(component(
		purl, "p2.eclipse.plugin", "com.google.gson", "1.0.0.5.v1", purl, "")))

	// Raw segments: "1", "0", "0%2E5", "v1" — four, the fourth non-numeric, so
	// the qualifier is dropped and the decoded version follows the same split.
	want := "pkg:maven/com.google.code.gson/gson@1.0.0.5"
	if purls[0] != want {
		t.Fatalf("purl = %q, want %q", purls[0], want)
	}
	if got := componentProperties(t, doc, 0)[p2.QualifierProperty]; got != "v1" {
		t.Fatalf("%s = %q, want %q", p2.QualifierProperty, got, "v1")
	}
}
