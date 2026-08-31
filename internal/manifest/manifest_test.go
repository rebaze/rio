package manifest_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/rebaze/rio/internal/manifest"
	"github.com/rebaze/rio/internal/sbom"
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
    sbom: "com.example.product.client/target/**/bom.json"
    subject:
      name: Example RCP Client
      version: 4.2.1
    transforms:
      - repair-purl:
          ecosystem: p2
          table: mapping/p2.yaml
      - repair-purl:

  - id: server-war
    sbom: "com.example.server.web/target/bom.json"

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
	if a.SBOM != "com.example.product.client/target/**/bom.json" {
		t.Errorf("Artifacts[0].SBOM = %q", a.SBOM)
	}
	if a.Subject == nil {
		t.Fatal("Artifacts[0].Subject is nil, want an override")
	}
	if a.Subject.Name != "Example RCP Client" || a.Subject.Version != "4.2.1" {
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
// list that can drift from it, and neither must this test.
func TestSpecVersionFloorAcceptsEverySupportedValue(t *testing.T) {
	if len(sbom.SupportedFloors) == 0 {
		t.Fatal("sbom.SupportedFloors is empty, this test would assert nothing")
	}
	for _, floor := range sbom.SupportedFloors {
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

// Every mapping a transform receives is a map[string]any, at every depth, so a
// transform can type-assert its way down without a special case.
func TestTransformConfigMapsAreStringKeyedAtEveryDepth(t *testing.T) {
	src := `version: 1
artifacts:
  - id: only
    sbom: bom.json
    transforms:
      - repair-purl:
          nested:
            deeper:
              key: value
          list:
            - two: 2
`
	m, err := manifest.Load(write(t, src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var check func(path string, v any)
	check = func(path string, v any) {
		switch got := v.(type) {
		case map[string]any:
			for k, child := range got {
				check(path+"."+k, child)
			}
		case []any:
			for i, child := range got {
				check(fmt.Sprintf("%s[%d]", path, i), child)
			}
		case map[any]any:
			t.Errorf("%s is a map[any]any; transform code asserting map[string]any would fail on it", path)
		}
	}
	for k, v := range m.Artifacts[0].Transforms[0].Config {
		check(k, v)
	}
}

// A merge key is yaml's own, not a config key, and what it merges in is
// string-keyed like everything else.
func TestTransformConfigAcceptsMergeKeys(t *testing.T) {
	src := `version: 1
artifacts:
  - id: only
    sbom: bom.json
    transforms:
      - repair-purl: &base
          ecosystem: p2
      - repair-purl:
          <<: *base
          table: mapping/p2.yaml
`
	m, err := manifest.Load(write(t, src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := transform.Config{"ecosystem": "p2", "table": "mapping/p2.yaml"}
	if diff := cmp.Diff(want, m.Artifacts[0].Transforms[1].Config); diff != "" {
		t.Errorf("merged config mismatch (-want +got):\n%s", diff)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := []struct {
		name  string
		src   string
		want  []string // every substring the error must contain
		avoid []string // and every substring it must not
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
			want: []string{"version", `the string "one"`},
		},
		// version is the compatibility lever (§9), so it is the integer 1 and
		// nothing that merely looks like it.
		{
			name: "version is a float",
			src:  "version: 1.0\nartifacts:\n  - id: a\n    sbom: bom.json\n",
			want: []string{"version", "must be the integer 1", "the number 1.0"},
		},
		{
			name: "version is a quoted string",
			src:  "version: \"1\"\nartifacts:\n  - id: a\n    sbom: bom.json\n",
			want: []string{"version", "must be the integer 1", `the string "1"`},
		},
		{
			name: "version is a boolean",
			src:  "version: true\nartifacts:\n  - id: a\n    sbom: bom.json\n",
			want: []string{"version", "the boolean true"},
		},
		{
			name: "version is empty",
			src:  "version:\nartifacts:\n  - id: a\n    sbom: bom.json\n",
			want: []string{"version", "no value"},
		},
		{
			name: "version is a date",
			src:  "version: 2001-12-14\nartifacts:\n  - id: a\n    sbom: bom.json\n",
			want: []string{"version", "2001-12-14"},
		},
		{
			name: "version is too large for an int",
			src:  "version: 9223372036854775808\nartifacts:\n  - id: a\n    sbom: bom.json\n",
			want: []string{"version", "9223372036854775808"},
		},
		{
			name: "version is a mapping",
			src:  "version: {}\nartifacts:\n  - id: a\n    sbom: bom.json\n",
			want: []string{"version", "a mapping"},
		},
		{
			name: "version is a list",
			src:  "version: []\nartifacts:\n  - id: a\n    sbom: bom.json\n",
			want: []string{"version", "a list"},
		},
		{
			// An alias is the one node kind that is neither scalar, mapping
			// nor sequence by the time it reaches an error message.
			name: "version is an alias",
			src:  "artifacts: &a\n  - id: x\n    sbom: y\nversion: *a\n",
			want: []string{"version", "an unexpected value"},
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
			// The config reaching a transform is plain string-keyed Go values
			// at every depth, so a key that is not a string is refused here
			// rather than left to surprise a transform.
			name: "transform config with a non-string key",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    transforms:\n      - repair-purl:\n          nested:\n            ? [a, b]\n            : v\n",
			want: []string{"artifacts[0].transforms[0]", "repair-purl", "config keys must be plain strings", "a list"},
		},
		{
			name: "transform config with a float key",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    transforms:\n      - repair-purl:\n          nested:\n            3.8: x\n",
			want: []string{"artifacts[0].transforms[0]", "config keys must be plain strings", "the number 3.8", "line 8"},
		},
		{
			name: "transform config with an int key",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    transforms:\n      - repair-purl:\n          5: x\n",
			want: []string{"artifacts[0].transforms[0]", "config keys must be plain strings", "the number 5"},
		},
		{
			name: "transform config with a boolean key",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    transforms:\n      - repair-purl:\n          nested:\n            true: x\n",
			want: []string{"config keys must be plain strings", "the boolean true"},
		},
		{
			name: "transform config with a null key",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    transforms:\n      - repair-purl:\n          nested:\n            ~: x\n",
			want: []string{"config keys must be plain strings", "no value"},
		},
		{
			// Inside a list, too: transform code walks whatever it is handed.
			name: "transform config with a non-string key inside a list",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    transforms:\n      - repair-purl:\n          list:\n            - 5: x\n",
			want: []string{"config keys must be plain strings", "the number 5", "line 8"},
		},
		{
			// A transform named 5 would reach the registry as "5" and be
			// reported as an unknown transform, hiding the real mistake.
			name: "transform name is a number",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    transforms:\n      - 5: {}\n",
			want: []string{"artifacts[0].transforms[0]", "must be a plain string", "the number 5"},
		},
		{
			name: "transform name is a boolean",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    transforms:\n      - true: {}\n",
			want: []string{"artifacts[0].transforms[0]", "must be a plain string", "the boolean true"},
		},
		{
			name: "transform name is empty",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    transforms:\n      - \"\": {}\n",
			want: []string{"artifacts[0].transforms[0]", "must be a plain string"},
		},
		{
			name: "transform entry is null",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    transforms:\n      - ~\n",
			want: []string{"artifacts[0].transforms[0]", "no value"},
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
			want: []string{`unknown key "outputs"`},
		},
		{
			name: "unknown artifact key",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    sboms: other.json\n",
			want: []string{"artifacts[0]", `unknown key "sboms"`},
		},
		{
			name: "unknown output key",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\noutput:\n  floor: \"1.6\"\n",
			want: []string{"output", `unknown key "floor"`},
		},
		{
			name: "unknown gate key",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\ngate:\n  required: [name]\n",
			want: []string{"gate", `unknown key "required"`},
		},
		{
			name: "unknown subject key",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    subject:\n      name: n\n      version: v\n      purl: pkg:maven/a/b@1\n",
			want: []string{"artifacts[0].subject", `unknown key "purl"`},
		},
		{
			// A key is whatever the author quoted, spaces and all.
			name: "unknown key containing a space",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    \"my key\": 1\n",
			want: []string{"artifacts[0]", `unknown key "my key"`},
		},
		{
			name: "unknown key that is empty",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    \"\": 1\n",
			want: []string{"artifacts[0]", `unknown key ""`},
		},
		// A value of the wrong shape names the key it was written under and
		// the shape that key must have, never the Go type this package
		// happens to decode it into (§10).
		{
			name: "artifacts is a scalar",
			src:  "version: 1\nartifacts: nope\n",
			want: []string{"artifacts: line 2", "must be a list of artifact entries", `the string "nope"`},
		},
		{
			name: "artifacts entry is a scalar",
			src:  "version: 1\nartifacts:\n  - nope\n",
			want: []string{"artifacts[0]: line 3", "must be a mapping with id and sbom", `the string "nope"`},
		},
		{
			name: "id is a list",
			src:  "version: 1\nartifacts:\n  - id: [a]\n    sbom: bom.json\n",
			want: []string{"artifacts[0].id: line 3", "must be a string", "a list"},
		},
		{
			name: "sbom is a mapping",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: {x: y}\n",
			want: []string{"artifacts[0].sbom: line 4", "must be a string", "a mapping"},
		},
		{
			name: "subject is a scalar",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    subject: thing\n",
			want: []string{"artifacts[0].subject: line 5", "must be a mapping with name and version", `the string "thing"`},
		},
		{
			name: "transforms is a mapping",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    transforms: {a: {}}\n",
			want: []string{"artifacts[0].transforms: line 5", "must be a list of transforms", "a mapping"},
		},
		{
			name: "output is a scalar",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\noutput: \"1.6\"\n",
			want: []string{"output: line 5", "must be a mapping", `the string "1.6"`},
		},
		{
			name: "specVersionFloor is a list",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\noutput:\n  specVersionFloor: [1.6]\n",
			want: []string{"output.specVersionFloor: line 6", "must be a string", "a list"},
		},
		{
			name: "gate is a list",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\ngate: [name]\n",
			want: []string{"gate: line 5", "must be a mapping", "a list"},
		},
		{
			name: "gate.require is a scalar",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\ngate:\n  require: name\n",
			want: []string{"gate.require: line 6", "must be a list of strings", `the string "name"`},
		},
		{
			name: "gate.require holds a list",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\ngate:\n  require: [[name]]\n",
			want: []string{"gate.require[0]: line 6", "must be a string", "a list"},
		},
		{
			name: "manifest is a list",
			src:  "- version: 1\n",
			want: []string{"line 1", "the manifest must be a mapping with version and artifacts", "a list"},
		},
		{
			// Two keys of the same type on one line cannot be told apart, so
			// the message drops the key rather than naming the wrong one.
			name: "two values of the wrong shape on one line",
			src:  "version: 1\nartifacts: [{id: [a], sbom: [b]}]\n",
			want: []string{"line 2", "must be a string", "a list"},
		},
		{
			// go-yaml reports the value it choked on, truncated past ten
			// characters, so finding the key it belongs to takes more than a
			// string comparison.
			name: "subject is a long scalar",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    subject: a very long thing indeed\n",
			want: []string{"artifacts[0].subject: line 5", `the string "a very long thing indeed"`},
		},
		{
			// Two entries on one line each carry an "x", so which mapping was
			// meant is unknowable; the section still gets named.
			name: "unknown key in one of two entries on a line",
			src:  "version: 1\nartifacts: [{id: a, sbom: b, x: 1}, {id: c, sbom: d, x: 2}]\n",
			want: []string{"artifacts", `unknown key "x"`},
		},
		{
			name: "duplicate top level key",
			src:  "version: 1\nversion: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n",
			want: []string{"line 2", `key "version" already defined`},
		},
		{
			name: "duplicate artifact key",
			src:  "version: 1\nartifacts:\n  - id: a\n    id: b\n    sbom: bom.json\n",
			want: []string{"line 4", `key "id" already defined`},
		},
		{
			name: "duplicate transform config key",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n    transforms:\n      - repair-purl:\n          ecosystem: p2\n          ecosystem: maven\n",
			want: []string{"artifacts[0].transforms[0]", "repair-purl", `key "ecosystem" already defined`},
			// go-yaml wraps its messages in a header nobody needs to read.
			avoid: []string{"unmarshal errors"},
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
			// The second document is parsed too, so its syntax errors are
			// reported like the first document's.
			name: "second document is not yaml",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n---\nartifacts: [\n",
			want: []string{"rio.yaml"},
		},
		{
			name: "second document",
			src:  "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n---\nversion: 1\n",
			want: []string{"more than one YAML document"},
		},
		{
			// The document after the marker is empty, so calling the file
			// "more than one document" describes it wrongly.
			name:  "trailing document marker",
			src:   "version: 1\nartifacts:\n  - id: a\n    sbom: bom.json\n---\n",
			want:  []string{`"---"`, "empty document", "remove the marker"},
			avoid: []string{"more than one"},
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
			for _, avoid := range tc.avoid {
				if strings.Contains(msg, avoid) {
					t.Errorf("error %q should not mention %q", msg, avoid)
				}
			}
			// A message about the manifest never names the Go types this
			// package reads it with: the author has never seen them (§10).
			// The path is exempt, being the author's own.
			detail := strings.ReplaceAll(msg, path, "")
			for _, leak := range []string{"manifest.", "yaml.Node", "[]string", "unmarshal", "not found in type"} {
				if strings.Contains(detail, leak) {
					t.Errorf("error %q leaks an internal detail: %q", msg, leak)
				}
			}
		})
	}
}

// One decode failure is one message, however many fields go-yaml blamed for
// it: the same sentence twice reads like two problems.
func TestOneMessagePerDistinctProblem(t *testing.T) {
	path := write(t, "version: 1\nartifacts: [{id: [a], sbom: [b]}]\n")
	_, err := manifest.Load(path)
	if err == nil {
		t.Fatal("Load succeeded, want an error")
	}
	if n := strings.Count(err.Error(), "must be a string"); n != 1 {
		t.Errorf("error %q states the same problem %d times, want once", err, n)
	}
}

// An explicitly empty require list is the empty subset (§2), not a mistake and
// not the default: the subject check still runs, no component field is
// required. Changing that would silently re-arm three checks.
func TestGateRequireEmptyIsTheEmptySubset(t *testing.T) {
	path := write(t, "version: 1\nartifacts:\n  - id: only\n    sbom: bom.json\ngate:\n  require: []\n")
	m, err := manifest.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(m.Gate.Require) != 0 {
		t.Fatalf("Gate.Require = %v, want the empty subset", m.Gate.Require)
	}
	for _, field := range manifest.DefaultRequire() {
		if m.Gate.Requires(field) {
			t.Errorf("Requires(%q) = true, want false", field)
		}
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

// A manifest that exists but cannot be read is not "not found": the two send
// the author looking in different places.
func TestLoadUnreadableFileIsNotReportedAsMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := manifest.Load(dir)
	if err == nil {
		t.Fatal("Load succeeded on a directory, want an error")
	}
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("error %q does not name the path %q", err, dir)
	}
	if strings.Contains(err.Error(), "not found") {
		t.Errorf("error %q calls an unreadable manifest missing", err)
	}
}

// A relative path is reported as given and as resolved, because the two differ
// by the working directory the caller happened to be in.
func TestLoadMissingRelativeFileNamesBothPaths(t *testing.T) {
	const rel = "no-such-directory/rio.yaml"
	_, err := manifest.Load(rel)
	if err == nil {
		t.Fatal("Load succeeded on a missing manifest, want an error")
	}
	abs, absErr := filepath.Abs(rel)
	if absErr != nil {
		t.Fatal(absErr)
	}
	for _, want := range []string{rel, abs} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
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
