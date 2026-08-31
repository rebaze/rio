package purl_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/rebaze/rio/internal/transform"
	_ "github.com/rebaze/rio/internal/transform/purl"
)

func TestRegisteredUnderTheManifestKey(t *testing.T) {
	var found bool
	for _, name := range transform.Names() {
		if name == "repair-purl" {
			found = true
		}
	}
	if !found {
		t.Fatalf("repair-purl not registered, known = %v", transform.Names())
	}
}

func TestDispatchToP2(t *testing.T) {
	tr, err := transform.New("repair-purl", transform.Config{"ecosystem": "p2"}, t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := tr.ID(); got != "repair-purl/p2" {
		t.Errorf("ID() = %q, want %q", got, "repair-purl/p2")
	}
}

func TestEcosystemErrors(t *testing.T) {
	cases := []struct {
		name          string
		cfg           transform.Config
		wantSubstring []string
	}{
		{"missing", transform.Config{}, []string{"ecosystem", "p2"}},
		{"empty", transform.Config{"ecosystem": ""}, []string{"ecosystem", "p2"}},
		{"unsupported", transform.Config{"ecosystem": "npm"}, []string{"npm", "p2"}},
		{"wrong type", transform.Config{"ecosystem": 2}, []string{"ecosystem"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := transform.New("repair-purl", tc.cfg, t.TempDir())
			if err == nil {
				t.Fatalf("want an error")
			}
			for _, want := range tc.wantSubstring {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to mention %q", err, want)
				}
			}
		})
	}
}

func TestUnknownConfigKeyIsRejected(t *testing.T) {
	_, err := transform.New("repair-purl", transform.Config{"ecosystem": "p2", "ecosytem": "p2"}, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "ecosytem") {
		t.Fatalf("err = %v, want it to name the typo", err)
	}
}

func TestTableIsResolvedRelativeToBaseDir(t *testing.T) {
	// A relative table path that does not exist under baseDir is a
	// configuration error naming the path (§10).
	_, err := transform.New("repair-purl",
		transform.Config{"ecosystem": "p2", "table": "mappings/absent.json"}, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "mappings/absent.json") {
		t.Fatalf("err = %v, want it to name the table path", err)
	}
}

// The describe seam `rio plan` reads through. The ecosystem leads, then the
// ecosystem's own keys, resolved.
func TestDescribeThroughTheRegistry(t *testing.T) {
	got, err := transform.Describe("repair-purl",
		transform.Config{"ecosystem": "p2", "table": "p2-maven.json"})
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	want := []transform.Option{
		{Key: "ecosystem", Value: "p2"},
		{Key: "table", Value: "p2-maven.json", Path: true},
		{Key: "groupPrefix", Value: "p2.", IsDefault: true},
		{Key: "classifier", Value: "osgi.bundle", IsDefault: true},
		{Key: "syntheticNamespace", Value: "p2.eclipse.plugin", IsDefault: true},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("Describe (-want +got):\n%s", diff)
	}
}

// Describe reads nothing. A table that does not exist yet is the state every
// repository starts in, and it is exactly what the plan is read to fix.
func TestDescribeDoesNotReadTheTable(t *testing.T) {
	if _, err := transform.Describe("repair-purl",
		transform.Config{"ecosystem": "p2", "table": "mappings/absent.json"}); err != nil {
		t.Fatalf("Describe refused a table that does not exist: %v", err)
	}
}

// Every configuration New refuses without touching the filesystem, Describe
// refuses in the same words, or a plan would describe a run rio cannot make.
func TestDescribeAndNewAgreeOnBadConfiguration(t *testing.T) {
	cases := []struct {
		name string
		id   string
		cfg  transform.Config
	}{
		{"unknown transform", "repair-everything", transform.Config{}},
		{"missing ecosystem", "repair-purl", transform.Config{}},
		{"unsupported ecosystem", "repair-purl", transform.Config{"ecosystem": "npm"}},
		{"ecosystem is not a string", "repair-purl", transform.Config{"ecosystem": 2}},
		{"unknown option", "repair-purl", transform.Config{"ecosystem": "p2", "ecosytem": "p2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, newErr := transform.New(tc.id, tc.cfg, t.TempDir())
			_, describeErr := transform.Describe(tc.id, tc.cfg)
			if newErr == nil || describeErr == nil {
				t.Fatalf("New err = %v, Describe err = %v, want both to fail", newErr, describeErr)
			}
			if newErr.Error() != describeErr.Error() {
				t.Fatalf("the two disagree:\n New:      %v\n Describe: %v", newErr, describeErr)
			}
		})
	}
}

// A nil config is an omitted one ("- repair-purl:"), and both entry points
// have to treat it the same way rather than one panicking on it.
func TestDescribeHandlesAnOmittedConfig(t *testing.T) {
	_, newErr := transform.New("repair-purl", nil, t.TempDir())
	_, describeErr := transform.Describe("repair-purl", nil)
	if newErr == nil || describeErr == nil || newErr.Error() != describeErr.Error() {
		t.Fatalf("New err = %v, Describe err = %v", newErr, describeErr)
	}
}
