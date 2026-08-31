package p2_test

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/rebaze/rio/internal/transform"
	"github.com/rebaze/rio/internal/transform/purl/p2"
)

func describe(t *testing.T, cfg transform.Config) p2.Scope {
	t.Helper()
	scope, err := p2.Describe(cfg)
	if err != nil {
		t.Fatalf("p2.Describe(%v): %v", cfg, err)
	}
	return scope
}

// The plan publishes the values in force, not the manifest's own words, so a
// consumer never carries a second copy of "p2." or "osgi.bundle" (§6.2).
func TestDescribeFillsInTheDefaults(t *testing.T) {
	got := describe(t, transform.Config{"ecosystem": "p2"})
	want := p2.Scope{
		Table:              "",
		GroupPrefix:        p2.DefaultGroupPrefix,
		Classifier:         p2.DefaultClassifier,
		SyntheticNamespace: p2.DefaultSyntheticNamespace,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("Describe (-want +got):\n%s", diff)
	}
}

func TestDescribeCarriesTheOverrides(t *testing.T) {
	got := describe(t, transform.Config{
		"ecosystem":          "p2",
		"table":              "mappings/p2-maven.json",
		"groupPrefix":        "acme.",
		"classifier":         "osgi.fragment",
		"syntheticNamespace": "acme.plugin",
	})
	want := p2.Scope{
		Table:              "mappings/p2-maven.json",
		GroupPrefix:        "acme.",
		Classifier:         "osgi.fragment",
		SyntheticNamespace: "acme.plugin",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("Describe (-want +got):\n%s", diff)
	}
}

// The table path is reported exactly as the manifest wrote it, because that is
// how the transform resolves it: relative to the manifest directory.
func TestDescribeDoesNotResolveTheTablePath(t *testing.T) {
	if got := describe(t, transform.Config{"ecosystem": "p2", "table": "p2-maven.json"}).Table; got != "p2-maven.json" {
		t.Fatalf("Table = %q, want it verbatim", got)
	}
}

// The property the whole plan rests on: a table that does not exist yet is
// describable, because the table is what the plan is read to produce. New
// still refuses it, so nothing about the transform itself has softened.
func TestDescribeSucceedsWhereNewCannot(t *testing.T) {
	dir := t.TempDir()
	cfg := transform.Config{"ecosystem": "p2", "table": "not-built-yet.json"}

	if got := describe(t, cfg).Table; got != "not-built-yet.json" {
		t.Fatalf("Table = %q", got)
	}
	if _, err := p2.New(cfg, dir); err == nil {
		t.Fatal("p2.New accepted a table file that does not exist")
	} else if !strings.Contains(err.Error(), filepath.Join(dir, "not-built-yet.json")) {
		t.Fatalf("p2.New error = %q, want it to name the missing table", err)
	}
}

// A plan that succeeds on a manifest rio normalize refuses would describe a
// run that cannot happen (§10). Every configuration failure that does not need
// the filesystem has to be reported by both, with the same words.
func TestDescribeAndNewRejectTheSameConfigurations(t *testing.T) {
	cases := []struct {
		name string
		cfg  transform.Config
	}{
		{"unknown key", transform.Config{"ecosystem": "p2", "tabel": "x.json"}},
		{"table is not a string", transform.Config{"ecosystem": "p2", "table": 7}},
		{"groupPrefix is not a string", transform.Config{"ecosystem": "p2", "groupPrefix": true}},
		{"classifier is not a string", transform.Config{"ecosystem": "p2", "classifier": []any{"a"}}},
		{"syntheticNamespace is not a string", transform.Config{"ecosystem": "p2", "syntheticNamespace": 1.5}},
		{"syntheticNamespace is empty", transform.Config{"ecosystem": "p2", "syntheticNamespace": "  "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, describeErr := p2.Describe(tc.cfg)
			_, newErr := p2.New(tc.cfg, t.TempDir())
			if describeErr == nil || newErr == nil {
				t.Fatalf("Describe err = %v, New err = %v, want both to fail", describeErr, newErr)
			}
			if describeErr.Error() != newErr.Error() {
				t.Fatalf("the two disagree:\n Describe: %v\n New:      %v", describeErr, newErr)
			}
		})
	}
}

// Options and the allowlist Describe enforces are the same list, so a key the
// transform starts honouring cannot stay invisible in a plan, and a key a plan
// advertises cannot be one the transform ignores. Both are read out of the
// package rather than restated here, or the test would just be a third copy.
func TestOptionsAndTheAcceptedKeysAreOneList(t *testing.T) {
	_, err := p2.Describe(transform.Config{"ecosystem": "p2", "nonsense": "x"})
	if err == nil {
		t.Fatal("Describe accepted an unknown key")
	}
	_, list, found := strings.Cut(err.Error(), "known options are ")
	if !found {
		t.Fatalf("the rejection does not list the known options: %v", err)
	}

	accepted := strings.Split(list, ", ")
	sort.Strings(accepted)

	// "ecosystem" belongs to the dispatch above this package, not to the scope.
	reported := []string{"ecosystem"}
	for _, opt := range describe(t, transform.Config{"ecosystem": "p2"}).Options() {
		reported = append(reported, opt.Key)
	}
	sort.Strings(reported)

	if diff := cmp.Diff(accepted, reported); diff != "" {
		t.Fatalf("the accepted keys and the reported options have drifted (-accepted +reported):\n%s", diff)
	}
}

// Every reported option carries the value in force, so none can be reported as
// an empty string by omission.
func TestEveryReportedOptionHasItsValue(t *testing.T) {
	opts := describe(t, transform.Config{"ecosystem": "p2", "table": "t.json"}).Options()
	want := []transform.Option{
		{Key: "table", Value: "t.json", Path: true},
		{Key: "groupPrefix", Value: p2.DefaultGroupPrefix, IsDefault: true},
		{Key: "classifier", Value: p2.DefaultClassifier, IsDefault: true},
		{Key: "syntheticNamespace", Value: p2.DefaultSyntheticNamespace, IsDefault: true},
	}
	if diff := cmp.Diff(want, opts); diff != "" {
		t.Fatalf("Options (-want +got):\n%s", diff)
	}
}

// IsDefault answers "is this the standard behaviour", which is what lets a
// human readable plan show only what a manifest changed. No override table is
// itself the default, so an absent table is not something to point at.
func TestOptionsFlagTheDefaults(t *testing.T) {
	for _, opt := range describe(t, transform.Config{"ecosystem": "p2"}).Options() {
		if !opt.IsDefault {
			t.Errorf("%q is reported as an override on a manifest that set nothing", opt.Key)
		}
	}
	for _, opt := range describe(t, transform.Config{
		"ecosystem":          "p2",
		"table":              "t.json",
		"groupPrefix":        "acme.",
		"classifier":         "osgi.fragment",
		"syntheticNamespace": "acme.plugin",
	}).Options() {
		if opt.IsDefault {
			t.Errorf("%q is reported as a default on a manifest that set it", opt.Key)
		}
	}
}

// The table is the only option that names a file, and saying so is what lets
// `rio plan` report a table that does not exist yet without knowing whose
// option it is looking at.
func TestOnlyTheTableIsAPath(t *testing.T) {
	for _, opt := range describe(t, transform.Config{"ecosystem": "p2"}).Options() {
		if want := opt.Key == "table"; opt.Path != want {
			t.Errorf("%q Path = %v, want %v", opt.Key, opt.Path, want)
		}
	}
}

// The built-in table is an asset the plan publishes so a generated override
// can stay a delta over it.
func TestBuiltinEntriesAreTheShippedAsset(t *testing.T) {
	entries, err := p2.BuiltinEntries()
	if err != nil {
		t.Fatalf("BuiltinEntries: %v", err)
	}
	if got, want := entries["com.google.gson"], (p2.Coordinates{GroupID: "com.google.code.gson", ArtifactID: "gson"}); got != want {
		t.Fatalf("com.google.gson = %+v, want %+v", got, want)
	}

	// A caller cannot edit the asset out from under the transform.
	entries["com.google.gson"] = p2.Coordinates{GroupID: "evil", ArtifactID: "evil"}
	again, err := p2.BuiltinEntries()
	if err != nil {
		t.Fatalf("BuiltinEntries: %v", err)
	}
	if again["com.google.gson"].GroupID != "com.google.code.gson" {
		t.Fatal("BuiltinEntries handed out the package's own map")
	}
}
