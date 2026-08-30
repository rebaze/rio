package sbom_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/sbom"
)

func TestValidateAcceptsEveryValidFixtureAtItsOwnVersion(t *testing.T) {
	valid := []string{
		"tycho-rcp.cdx.json",
		"plain-maven.cdx.json",
		"gate-missing-version.cdx.json",
		"uplift-1.4.cdx.json",
		"evidence-1.5-object.cdx.json",
		"unmodelled-fields.cdx.json",
	}
	for _, name := range valid {
		t.Run(name, func(t *testing.T) {
			data := fixture(t, name)
			doc := load(t, data)
			if err := sbom.Validate(data, doc.SpecVersion()); err != nil {
				t.Fatalf("Validate(%s at %s) = %v, want nil", name, doc.SpecVersion(), err)
			}
		})
	}
}

// §11 fixture 7: a document invalid at its own declared spec version.
func TestValidateReportsViolationsWithTheirPath(t *testing.T) {
	data := fixture(t, "invalid-1.6.cdx.json")

	err := sbom.Validate(data, "1.6")
	if err == nil {
		t.Fatal("Validate() = nil, want a violation")
	}

	var verr *sbom.ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("Validate() = %T, want *sbom.ValidationError", err)
	}
	if verr.SpecVersion != "1.6" {
		t.Fatalf("SpecVersion = %q, want %q", verr.SpecVersion, "1.6")
	}
	if len(verr.Violations) != 1 {
		t.Fatalf("Violations = %+v, want exactly one", verr.Violations)
	}
	if got, want := verr.Violations[0].Path, "/components/0/type"; got != want {
		t.Fatalf("Violations[0].Path = %q, want %q", got, want)
	}
	if !strings.Contains(err.Error(), "/components/0/type") {
		t.Fatalf("Error() = %q, want it to name the schema path of the violation", err)
	}
}

// §11 fixture 6: above the highest embedded schema, validation is skipped and
// recorded, never an error (§3).
func TestValidateReportsNoSchemaAboveTheHighestEmbeddedVersion(t *testing.T) {
	data := fixture(t, "future-1.9.cdx.json")

	err := sbom.Validate(data, "1.9")
	var noSchema *sbom.ErrNoSchema
	if !errors.As(err, &noSchema) {
		t.Fatalf("Validate() = %v (%T), want *sbom.ErrNoSchema", err, err)
	}
	if noSchema.SpecVersion != "1.9" {
		t.Fatalf("ErrNoSchema.SpecVersion = %q, want %q", noSchema.SpecVersion, "1.9")
	}
	if !strings.Contains(err.Error(), "1.9") {
		t.Fatalf("Error() = %q, want it to name the spec version", err)
	}
}

func TestSchemaAvailable(t *testing.T) {
	// §5 step 2b requires validating the input at its ORIGINAL version, and
	// the real fixture is 1.4, so every version rio can read must be covered.
	for _, v := range []string{"1.2", "1.3", "1.4", "1.5", "1.6"} {
		if !sbom.SchemaAvailable(v) {
			t.Errorf("SchemaAvailable(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"1.0", "1.1", "1.7", "2.0", "", "nonsense"} {
		if sbom.SchemaAvailable(v) {
			t.Errorf("SchemaAvailable(%q) = true, want false", v)
		}
	}
	if sbom.HighestSchemaVersion != "1.6" {
		t.Fatalf("HighestSchemaVersion = %q, want 1.6", sbom.HighestSchemaVersion)
	}
}

func TestValidateSelfUsesTheDocumentsCurrentVersion(t *testing.T) {
	doc := load(t, fixture(t, "uplift-1.4.cdx.json"))
	if err := doc.ValidateSelf(); err != nil {
		t.Fatalf("ValidateSelf() at 1.4 = %v, want nil", err)
	}
	if _, _, err := doc.Uplift("1.6"); err != nil {
		t.Fatal(err)
	}
	if err := doc.ValidateSelf(); err != nil {
		t.Fatalf("ValidateSelf() after uplift to 1.6 = %v, want nil", err)
	}
}

func TestValidateRejectsNonJSON(t *testing.T) {
	if err := sbom.Validate([]byte("{"), "1.6"); err == nil {
		t.Fatal("Validate() = nil, want an error")
	}
}

// Schema resolution must never touch the network: the $refs between the
// CycloneDX schemas resolve against the embedded copies (§8).
func TestEmbeddedSchemasResolveTheirRefsLocally(t *testing.T) {
	// jsf-0.82 is referenced from 1.4 onwards and spdx from 1.2 onwards. A
	// document exercising both compiles only if both resolved.
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
"components":[{"type":"library","name":"a","version":"1",
  "licenses":[{"license":{"id":"Apache-2.0"}}]}],
"signature":{"algorithm":"RS256","value":"AAAA"}}`
	if err := sbom.Validate([]byte(doc), "1.6"); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestEmbeddedSchemaSetMatchesTheDirectory(t *testing.T) {
	// Guards against a stray file landing in the embedded directory, which is
	// how the schemas would silently pick up a fixture.
	names, err := filepath.Glob(filepath.Join("schemas", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"bom-1.2.schema.json": true, "bom-1.3.schema.json": true,
		"bom-1.4.schema.json": true, "bom-1.5.schema.json": true,
		"bom-1.6.schema.json": true, "jsf-0.82.schema.json": true,
		"spdx.schema.json": true,
	}
	for _, n := range names {
		base := filepath.Base(n)
		if !want[base] {
			t.Errorf("unexpected file in the embedded schema directory: %s", base)
		}
		delete(want, base)
	}
	for missing := range want {
		t.Errorf("missing embedded schema: %s", missing)
	}
	if _, err := os.Stat(filepath.Join("schemas", "bom-1.6.schema.json")); err != nil {
		t.Fatal(err)
	}
}
