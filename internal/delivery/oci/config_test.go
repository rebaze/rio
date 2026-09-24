package oci

import (
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func node(t testing.TB, s string) yaml.Node {
	t.Helper()
	var n yaml.Node
	if e := yaml.Unmarshal([]byte(s), &n); e != nil {
		t.Fatal(e)
	}
	return *n.Content[0]
}
func describe(t testing.TB, tail string) delivery.Description {
	t.Helper()
	d, e := (Provider{Directory: t.TempDir()}).Describe(node(t, "registry: REGISTRY.example:443\nrepository: acme/app\nauth: {anonymous: true}\n"+tail), node(t, "{}"), delivery.Subject{})
	if e != nil {
		t.Fatal(e)
	}
	d.DestinationName = "registry"
	return d
}
func TestDescribeCanonicalOffline(t *testing.T) {
	for _, tc := range []struct{ input, want string }{{"REGISTRY.example:443", "registry.example"}, {"[::1]:443", "[::1]"}, {"[2001:db8::1]:5000", "[2001:db8::1]:5000"}, {"localhost:5000", "localhost:5000"}} {
		d, e := (Provider{}).Describe(node(t, "registry: '"+tc.input+"'\nrepository: product-key/a.b_c--d\nauth: {usernameEnv: ABSENT_USER, passwordEnv: ABSENT_PASSWORD}\ncaFile: /missing/ca.pem"), node(t, "{}"), delivery.Subject{})
		if e != nil {
			t.Fatal(e)
		}
		o, _, e := ValidateDescription(d)
		if e != nil || o.Registry != tc.want {
			t.Fatal(o, e)
		}
		if !reflect.DeepEqual(d.Capabilities, []string{"submit", "observe-content"}) {
			t.Fatal(d)
		}
	}
	for _, media := range []string{ManifestMediaType, IndexMediaType, DockerManifestMediaType, DockerIndexMediaType} {
		d := describe(t, "subject: {digest: 'sha256:"+strings.Repeat("1", 64)+"', mediaType: '"+media+"', size: 527}\n")
		if !delivery.HasCapability(d, "observe-referrers") {
			t.Fatal(d)
		}
	}
}
func TestDescribeRejectsInvalid(t *testing.T) {
	base := "registry: registry.example\nrepository: acme/app\nauth: {anonymous: true}\n"
	cases := []string{
		"registry: https://example.com\nrepository: a\nauth: {anonymous: true}", "registry: user@example.com\nrepository: a\nauth: {anonymous: true}", "registry: example.com/path\nrepository: a\nauth: {anonymous: true}", "registry: example.com?\nrepository: a\nauth: {anonymous: true}", "registry: example.com#x\nrepository: a\nauth: {anonymous: true}", "registry: example.com:0\nrepository: a\nauth: {anonymous: true}", "registry: '::1'\nrepository: a\nauth: {anonymous: true}",
		base + "tag: latest", base + "publication: {}", base + "project: {}", base + "autoCreate: false", base + "registry: again", base + "subject: {}", base + "subject: {digest: foo, mediaType: x, size: 1}", base + "subject: {digest: 'sha256:" + strings.Repeat("1", 64) + "', mediaType: application/vnd.oci.image.manifest.v1+json, size: 4194305}", base + "subject: {digest: 'sha256:" + strings.Repeat("1", 64) + "', mediaType: application/vnd.oci.image.manifest.v1+json, size: '3'}", base + "allowHTTP: 'true'", base + "caFile: null", base + "tokenServiceOrigins: [http://auth.example.com]", base + "tokenServiceOrigins: [https://auth.example.com/path]", base + "tokenServiceOrigins: [https://user@auth.example.com]", base + "tokenServiceOrigins: [https://auth.example.com, https://auth.example.com]",
	}
	for _, repo := range []string{"Acme/app", "a:tag", "a@sha256:bad", "/a", "a/../b", "a%2fb", "a//b", "a\\b", "a/", "a..b"} {
		cases = append(cases, strings.Replace(base, "acme/app", repo, 1))
	}
	for _, auth := range []string{"{}", "{anonymous: false}", "{anonymous: true, usernameEnv: USER}", "{usernameEnv: USER}", "{usernameEnv: USER, passwordEnv: PASSWORD, bearerTokenEnv: TOKEN}", "{username: literal, password: literal}", "{bearerTokenEnv: 12}", "{bearerTokenEnv: BAD-NAME}", "null"} {
		cases = append(cases, strings.Replace(base, "{anonymous: true}", auth, 1))
	}
	for i, input := range cases {
		if _, e := (Provider{}).Describe(node(t, input), node(t, "{}"), delivery.Subject{}); e == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
func sourceRef() (delivery.Source, delivery.PayloadRef) {
	h := delivery.Digest([]byte("synthetic SBOM bytes\n"))
	return delivery.Source{IndexSHA256: strings.Repeat("a", 64), OutputSHA256: h, ArtifactID: "app", Gate: "ok", SchemaValidated: true}, delivery.PayloadRef{Role: "sbom", MediaType: SBOMMediaType, SHA256: h, SourceSHA256: h, Size: 21, Transformation: "identity"}
}
func TestPrepareDeterministicEnvelope(t *testing.T) {
	s, ref := sourceRef()
	d := describe(t, "")
	p, e := (Provider{}).Prepare(d, s, []delivery.PayloadRef{ref})
	if e != nil {
		t.Fatal(e)
	}
	o, id, e := ValidateDescription(p.Description)
	if e != nil {
		t.Fatal(e)
	}
	gold, e := os.ReadFile("testdata/standalone-manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	if o.Publication.ManifestJSON != string(gold) {
		t.Fatalf("manifest differs: %s", o.Publication.ManifestJSON)
	}
	pub := o.Publication
	if pub.Manifest.Digest != "sha256:"+delivery.Digest(gold) || pub.Manifest.Size != int64(len(gold)) || id.Tag != "rio-sbom-sha256-"+delivery.Digest(gold) {
		t.Fatal(pub, id)
	}
	if pub.Config.Digest != "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" || pub.Config.Size != 2 {
		t.Fatal(pub.Config)
	}
	again, e := (Provider{}).Prepare(d, s, []delivery.PayloadRef{ref})
	if e != nil || !reflect.DeepEqual(p, again) {
		t.Fatal("nondeterministic", e)
	}
	if len(p.ExpectedReferences) != 3 || p.ExpectedReferences[0].Kind != "oci:manifest" || p.ExpectedReferences[1].Value != "sha256:"+ref.SHA256 || p.ExpectedReferences[2].Kind != "oci:tag" {
		t.Fatal(p.ExpectedReferences)
	}
	intent := record.Intent{Source: s, Payloads: []delivery.PayloadRef{ref}, Destination: p.Description, ExpectedReferences: p.ExpectedReferences}
	if e = ValidateIntent(intent); e != nil {
		t.Fatal(e)
	}
	s.IndexSHA256 = strings.Repeat("b", 64)
	changed, e := (Provider{}).Prepare(d, s, []delivery.PayloadRef{ref})
	if e != nil || delivery.JSONEqual(changed.Description.Identity, p.Description.Identity) {
		t.Fatal("index digest not bound", e)
	}
	intent.Source = s
	if e = ValidateIntent(intent); e == nil {
		t.Fatal("source drift accepted")
	}
}
func TestPrepareAttachedAndSavedTampering(t *testing.T) {
	s, ref := sourceRef()
	d := describe(t, "subject: {digest: 'sha256:"+strings.Repeat("1", 64)+"', mediaType: '"+IndexMediaType+"', size: 512}\n")
	p, e := (Provider{}).Prepare(d, s, []delivery.PayloadRef{ref})
	if e != nil {
		t.Fatal(e)
	}
	o, _, e := ValidateDescription(p.Description)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.ExpectedReferences) != 4 || o.Publication.Subject == nil || o.Publication.Subject.Digest == o.Publication.Manifest.Digest {
		t.Fatal(p)
	}
	for _, field := range []string{"manifestJSON", "digest", "subject", "unknown"} {
		q := p.Description
		var m map[string]any
		json.Unmarshal(q.Options, &m)
		pub := m["publication"].(map[string]any)
		switch field {
		case "manifestJSON":
			pub[field] = pub[field].(string) + "\n"
		case "digest":
			pub["manifest"].(map[string]any)["Digest"] = "sha256:" + strings.Repeat("2", 64)
		case "subject":
			m["Subject"] = m["subject"]
		case "unknown":
			m["unknown"] = true
		}
		q.Options, _ = json.Marshal(m)
		if _, _, e = ValidateDescription(q); e == nil {
			t.Fatal("tampering accepted", field)
		}
	}
	for _, path := range []string{"/old/missing/ca.pem", `C:\old\missing\ca.pem`, `\\oldhost\share\ca.pem`} {
		q := p.Description
		var m map[string]any
		json.Unmarshal(q.Options, &m)
		m["caFile"] = path
		q.Options, _ = json.Marshal(m)
		if _, _, e = ValidateDescription(q); e != nil {
			t.Fatal("historical CA host-resolved", filepath.VolumeName(path), e)
		}
	}
}

func TestDescribeSavedAuthPresence(t *testing.T) {
	d := describe(t, "")
	var m map[string]any
	json.Unmarshal(d.Options, &m)
	m["auth"] = map[string]any{"usernameEnv": "USER", "passwordEnv": "PASSWORD", "anonymous": false}
	d.Options, _ = json.Marshal(m)
	d.CredentialRefs = []string{"USER", "PASSWORD"}
	if _, _, e := ValidateDescription(d); e == nil {
		t.Fatal("saved false anonymous accepted with Basic form")
	}
}
func TestDescribeExactSubjectSizeLimit(t *testing.T) {
	d := describe(t, "subject: {digest: 'sha256:"+strings.Repeat("1", 64)+"', mediaType: '"+ManifestMediaType+"', size: 4194304}\n")
	if _, _, e := ValidateDescription(d); e != nil {
		t.Fatal("exact subject limit refused", e)
	}
}
