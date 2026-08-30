package manifest_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/rebaze/rio/internal/manifest"
	"github.com/rebaze/rio/internal/transform"
)

// write puts src in a fresh temp directory and returns the manifest path.
func write(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rio.yaml")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}

const fullManifest = `version: 1

artifacts:
  - id: rcp-client
    sbom: "com.tkse.product.client/target/**/bom.json"
    subject:
      name: TKSE RCP Client
      version: 4.2.1
    transforms:
      - repair-purl:
          ecosystem: p2
          table: mapping/p2.yaml
      - repair-purl:

  - id: server-war
    sbom: "com.tkse.server.web/target/bom.json"

output:
  specVersionFloor: "1.5"

gate:
  require: [name, purl]
`

func TestLoadFullManifest(t *testing.T) {
	path := write(t, fullManifest)
	m, err := manifest.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if m.Version != 1 {
		t.Errorf("Version = %d, want 1", m.Version)
	}
	if m.Path != path {
		t.Errorf("Path = %q, want %q", m.Path, path)
	}
	if want := filepath.Dir(path); m.Dir != want {
		t.Errorf("Dir = %q, want %q", m.Dir, want)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if want := hex.EncodeToString(sum[:]); m.SHA256 != want {
		t.Errorf("SHA256 = %q, want %q", m.SHA256, want)
	}
	if m.SHA256 != strings.ToLower(m.SHA256) {
		t.Errorf("SHA256 = %q, want lowercase hex", m.SHA256)
	}

	if len(m.Artifacts) != 2 {
		t.Fatalf("got %d artifacts, want 2", len(m.Artifacts))
	}

	a := m.Artifacts[0]
	if a.ID != "rcp-client" {
		t.Errorf("Artifacts[0].ID = %q", a.ID)
	}
	if a.SBOM != "com.tkse.product.client/target/**/bom.json" {
		t.Errorf("Artifacts[0].SBOM = %q", a.SBOM)
	}
	if a.Subject == nil {
		t.Fatal("Artifacts[0].Subject is nil, want an override")
	}
	if a.Subject.Name != "TKSE RCP Client" || a.Subject.Version != "4.2.1" {
		t.Errorf("Artifacts[0].Subject = %+v", *a.Subject)
	}

	// Transform order is the order given, and a null config arrives as an
	// empty (never nil-unusable) Config.
	if len(a.Transforms) != 2 {
		t.Fatalf("got %d transforms, want 2", len(a.Transforms))
	}
	if a.Transforms[0].Name != "repair-purl" || a.Transforms[1].Name != "repair-purl" {
		t.Errorf("transform names = %q, %q", a.Transforms[0].Name, a.Transforms[1].Name)
	}
	wantCfg := transform.Config{"ecosystem": "p2", "table": "mapping/p2.yaml"}
	if diff := cmp.Diff(wantCfg, a.Transforms[0].Config); diff != "" {
		t.Errorf("transform config mismatch (-want +got):\n%s", diff)
	}
	if len(a.Transforms[1].Config) != 0 {
		t.Errorf("null config = %#v, want empty", a.Transforms[1].Config)
	}

	b := m.Artifacts[1]
	if b.ID != "server-war" || b.Subject != nil || len(b.Transforms) != 0 {
		t.Errorf("Artifacts[1] = %+v", b)
	}

	if m.Output.SpecVersionFloor != "1.5" {
		t.Errorf("Output.SpecVersionFloor = %q, want 1.5", m.Output.SpecVersionFloor)
	}
	if diff := cmp.Diff([]string{"name", "purl"}, m.Gate.Require); diff != "" {
		t.Errorf("Gate.Require mismatch (-want +got):\n%s", diff)
	}
}

func TestLoadDefaults(t *testing.T) {
	path := write(t, "version: 1\nartifacts:\n  - id: only\n    sbom: bom.json\n")
	m, err := manifest.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if m.Output.SpecVersionFloor != "1.6" {
		t.Errorf("Output.SpecVersionFloor = %q, want the 1.6 default", m.Output.SpecVersionFloor)
	}
	if diff := cmp.Diff([]string{"name", "version", "purl"}, m.Gate.Require); diff != "" {
		t.Errorf("Gate.Require mismatch (-want +got):\n%s", diff)
	}
	if m.Artifacts[0].Subject != nil {
		t.Errorf("Subject = %+v, want nil when absent", m.Artifacts[0].Subject)
	}
	if m.Artifacts[0].Transforms != nil {
		t.Errorf("Transforms = %+v, want nil when absent", m.Artifacts[0].Transforms)
	}
}

// Sections present but empty still get their defaults.
func TestLoadEmptySections(t *testing.T) {
	path := write(t, "version: 1\nartifacts:\n  - id: only\n    sbom: bom.json\noutput:\ngate:\n")
	m, err := manifest.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if m.Output.SpecVersionFloor != "1.6" {
		t.Errorf("Output.SpecVersionFloor = %q, want 1.6", m.Output.SpecVersionFloor)
	}
	if diff := cmp.Diff([]string{"name", "version", "purl"}, m.Gate.Require); diff != "" {
		t.Errorf("Gate.Require mismatch (-want +got):\n%s", diff)
	}
}

func TestGateRequires(t *testing.T) {
	path := write(t, "version: 1\nartifacts:\n  - id: only\n    sbom: bom.json\ngate:\n  require: [purl]\n")
	m, err := manifest.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !m.Gate.Requires(manifest.RequirePURL) {
		t.Error("Requires(purl) = false, want true")
	}
	if m.Gate.Requires(manifest.RequireVersion) {
		t.Error("Requires(version) = true, want false")
	}
}

// The floor set is owned by internal/sbom; the manifest must not grow a second
// list that can drift from it.
func TestSpecVersionFloorAcceptsEverySupportedValue(t *testing.T) {
	for _, floor := range []string{"1.5", "1.6"} {
		src := "version: 1\nartifacts:\n  - id: only\n    sbom: bom.json\noutput:\n  specVersionFloor: \"" + floor + "\"\n"
		m, err := manifest.Load(write(t, src))
		if err != nil {
			t.Fatalf("floor %s: %v", floor, err)
		}
		if m.Output.SpecVersionFloor != floor {
			t.Errorf("floor %s: got %q", floor, m.Output.SpecVersionFloor)
		}
	}
}

func TestAcceptedIDs(t *testing.T) {
	for _, id := range []string{"a", "0", "rcp-client", "server.war", "a_b-c.9"} {
		src := "version: 1\nartifacts:\n  - id: " + id + "\n    sbom: bom.json\n"
		if _, err := manifest.Load(write(t, src)); err != nil {
			t.Errorf("id %q rejected: %v", id, err)
		}
	}
}

// Transform config must arrive as plain Go values all the way down, so
// internal/transform can consume it without knowing about YAML.
func TestTransformConfigIsPlainGoValues(t *testing.T) {
	src := `version: 1
artifacts:
  - id: only
    sbom: bom.json
    transforms:
      - repair-purl:
          ecosystem: p2
          nested:
            deeper:
              key: value
          list:
            - one
            - two: 2
          count: 3
          on: true
`
	m, err := manifest.Load(write(t, src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := m.Artifacts[0].Transforms[0].Config
	want := transform.Config{
		"ecosystem": "p2",
		"nested":    map[string]any{"deeper": map[string]any{"key": "value"}},
		"list":      []any{"one", map[string]any{"two": 2}},
		"count":     3,
		"on":        true,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("config mismatch (-want +got):\n%s", diff)
	}

	// The declared type is transform.Config, so its helpers work directly.
	eco, err := got.String("ecosystem", "")
	if err != nil || eco != "p2" {
		t.Errorf("Config.String(ecosystem) = %q, %v", eco, err)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string // every substring the error must contain
	}{
		{
			name: "version missing",
			src:  "artifacts:\n  - id: a\n    sbom: bom.json\n",
			want: []string{"version"},
		},
		{
			name: "version not 1",
			src:  "version: 2\nartifacts:\n  - id: a\n    sbom: bom.json\n",
			want: []string{"version", "2"},
		},
		{
			name: "version not a number",
			src:  "version: one\nartifacts:\n  - id: a\n    sbom: bom.json\n",
			want: []string{"version", "one"},
		},
		{
			name: "artifacts missing",
			src:  "version: 1\n",
			want: []string{"artifacts"},
		},
		{
			name: "artifacts empty",
			src:  "version: 1\nartifacts: []\n",
			want: []string{"artifacts"},
		},
		{
			name: "id missing",
			src:  "version: 1\nartifacts:\n  - sbom: bom.json\n",
			want: []string{"artifacts[0].id"},
		},
		{
			name: "id uppercase",
			src:  "version: 1\nartifacts:\n  - id: RCP\n    sbom: bom.json\n",
			want: []string{"artifacts[0].id", "RCP"},
		},
		{
			name: "id leading dash",
			src:  "version: 1\nartifacts:\n  - id: -rcp\n    sbom: bom.json\n",
			want: []string{"artifacts[0].id", "-rcp"},
		},
		{
			name: "id with slash",
			src:  "version: 1\nartifacts:\n  - id: a/b\n    sbom: bom.json\n",
			want: []string{"artifacts[0].id", "a/b"},
		},
		{
			name: "id with space",
			src:  "version: 1\nartifacts:\n  - id: a b\n    sbom: bom.json\n",
			want: []string{"artifacts[0].id"},
		},
		{
			name: "duplicate id",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: one.json\n  - id: a\n    sbom: two.json\n",
			want: []string{"artifacts[1].id", "a", "artifacts[0]"},
		},
		{
			name: "sbom missing",
			src:  "version: 1\nartifacts:\n  - id: a\n",
			want: []string{"artifacts[0].sbom"},
		},
		{
			name: "sbom empty",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: \"\"\n",
			want: []string{"artifacts[0].sbom"},
		},
		{
			name: "transform entry with no keys",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    transforms:\n      - {}\n",
			want: []string{"artifacts[0].transforms[0]"},
		},
		{
			name: "transform entry with two keys",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    transforms:\n      - repair-purl: {}\n        other: {}\n",
			want: []string{"artifacts[0].transforms[0]", "repair-purl", "other"},
		},
		{
			name: "transform entry is a scalar",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    transforms:\n      - repair-purl\n",
			want: []string{"artifacts[0].transforms[0]"},
		},
		{
			name: "transform config is a scalar",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    transforms:\n      - repair-purl: p2\n",
			want: []string{"artifacts[0].transforms[0]", "repair-purl"},
		},
		{
			// yaml.v3 refuses a non-string key rather than handing back a
			// map[any]any, so the config reaching a transform is always
			// plain string-keyed Go values.
			name: "transform config with a non-string key",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    transforms:\n      - repair-purl:\n          nested:\n            ? [a, b]\n            : v\n",
			want: []string{"artifacts[0].transforms[0]", "repair-purl"},
		},
		{
			name: "subject without version",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    subject:\n      name: Thing\n",
			want: []string{"artifacts[0].subject.version"},
		},
		{
			name: "subject without name",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    subject:\n      version: 1.0.0\n",
			want: []string{"artifacts[0].subject.name"},
		},
		{
			name: "spec version floor too low",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\noutput:\n  specVersionFloor: \"1.4\"\n",
			want: []string{"output.specVersionFloor", "1.4", "1.5", "1.6"},
		},
		{
			name: "spec version floor empty",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\noutput:\n  specVersionFloor: \"\"\n",
			want: []string{"output.specVersionFloor"},
		},
		{
			name: "gate requires unknown field",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\ngate:\n  require: [name, license]\n",
			want: []string{"gate.require", "license"},
		},
		{
			name: "gate requires duplicate",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\ngate:\n  require: [name, name]\n",
			want: []string{"gate.require", "name"},
		},
		{
			name: "unknown top level key",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\noutputs:\n  specVersionFloor: \"1.6\"\n",
			want: []string{"outputs"},
		},
		{
			name: "unknown artifact key",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    sboms: other.json\n",
			want: []string{"sboms"},
		},
		{
			name: "unknown output key",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\noutput:\n  floor: \"1.6\"\n",
			want: []string{"floor"},
		},
		{
			name: "unknown gate key",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\ngate:\n  required: [name]\n",
			want: []string{"required"},
		},
		{
			name: "unknown subject key",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    subject:\n      name: n\n      version: v\n      purl: pkg:maven/a/b@1\n",
			want: []string{"purl"},
		},
		{
			name: "not yaml",
			src:  "version: 1\nartifacts: [\n",
			want: []string{"rio.yaml"},
		},
		{
			name: "empty file",
			src:  "",
			want: []string{"rio.yaml", "empty"},
		},
		{
			name: "second document",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n---\nversion: 1\n",
			want: []string{"rio.yaml"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := write(t, tc.src)
			m, err := manifest.Load(path)
			if err == nil {
				t.Fatalf("Load succeeded, want an error; got %+v", m)
			}
			msg := err.Error()
			// Every configuration error names the manifest path (§10).
			if !strings.Contains(msg, path) {
				t.Errorf("error %q does not name the manifest path %q", msg, path)
			}
			for _, want := range tc.want {
				if !strings.Contains(msg, want) {
					t.Errorf("error %q does not mention %q", msg, want)
				}
			}
		})
	}
}

func TestLoadMissingFileNamesPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rio.yaml")
	_, err := manifest.Load(path)
	if err == nil {
		t.Fatal("Load succeeded on a missing manifest, want an error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the path it looked for (%q)", err, path)
	}
}

// A relative path still yields an absolute Dir, because globs and table paths
// resolve against it (§2).
func TestDirIsAbsolute(t *testing.T) {
	path := write(t, "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n")
	rel, err := filepath.Rel(mustGetwd(t), path)
	if err != nil {
		t.Skipf("no relative path from cwd: %v", err)
	}
	m, err := manifest.Load(rel)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !filepath.IsAbs(m.Dir) {
		t.Errorf("Dir = %q, want an absolute path", m.Dir)
	}
	if want := filepath.Dir(path); m.Dir != want {
		t.Errorf("Dir = %q, want %q", m.Dir, want)
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}
