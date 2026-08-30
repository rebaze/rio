package sbom_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/rebaze/rio/internal/sbom"
)

func TestUpliftRaisesToTheFloor(t *testing.T) {
	doc := load(t, fixture(t, "uplift-1.4.cdx.json"))

	applied, from, err := doc.Uplift("1.6")
	if err != nil {
		t.Fatalf("Uplift() = %v", err)
	}
	if !applied {
		t.Fatal("Uplift() reported no change, want a 1.4 to 1.6 uplift")
	}
	if from != "1.4" {
		t.Fatalf("Uplift() from = %q, want %q", from, "1.4")
	}
	if got := doc.SpecVersion(); got != "1.6" {
		t.Fatalf("SpecVersion() = %q, want %q", got, "1.6")
	}

	out, err := doc.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := sbom.Validate(out, "1.6"); err != nil {
		t.Fatalf("the uplifted document is not valid 1.6: %v", err)
	}
}

func TestUpliftIsANoOpAtOrAboveTheFloor(t *testing.T) {
	cases := []struct{ name, file string }{
		{"already at the floor", "plain-maven.cdx.json"},
		{"above every schema rio embeds", "future-1.9.cdx.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := fixture(t, tc.file)
			doc := load(t, data)
			before := doc.SpecVersion()

			applied, from, err := doc.Uplift("1.6")
			if err != nil {
				t.Fatalf("Uplift() = %v", err)
			}
			if applied {
				t.Fatalf("Uplift() applied at spec version %s, want a no-op", before)
			}
			if from != before {
				t.Fatalf("Uplift() from = %q, want %q", from, before)
			}

			out, err := doc.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tree(t, data), tree(t, out)); diff != "" {
				t.Fatalf("a no-op uplift changed the document (-before +after):\n%s", diff)
			}
		})
	}
}

func TestUpliftRewritesSchemaOnlyWhenTheInputCarriedOne(t *testing.T) {
	t.Run("present is rewritten", func(t *testing.T) {
		doc := load(t, fixture(t, "evidence-1.5-object.cdx.json"))
		if _, _, err := doc.Uplift("1.6"); err != nil {
			t.Fatal(err)
		}
		out, err := doc.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if want := sbom.SchemaURL("1.6"); !bytes.Contains(out, []byte(want)) {
			t.Fatalf("$schema was not rewritten to %q:\n%s", want, out)
		}
	})

	t.Run("absent is not added", func(t *testing.T) {
		doc := load(t, fixture(t, "uplift-1.4.cdx.json"))
		if _, _, err := doc.Uplift("1.6"); err != nil {
			t.Fatal(err)
		}
		out, err := doc.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		// Adding a $schema the generator did not write is a change rio was not
		// asked to make (§5 step 2).
		if bytes.Contains(out, []byte(`"$schema"`)) {
			t.Fatalf("uplift added a $schema key that the input did not have:\n%s", out)
		}
	})
}

// evidence.identity is an object at 1.5 and an array at 1.6. Wrap it, keeping
// its content (§5 step 2, §11 fixture 5).
func TestUpliftWrapsIdentityEvidenceIntoAnArray(t *testing.T) {
	doc := load(t, fixture(t, "evidence-1.5-object.cdx.json"))
	if _, _, err := doc.Uplift("1.6"); err != nil {
		t.Fatal(err)
	}

	entries := identityEntries(t, doc, 0)
	if len(entries) != 1 {
		t.Fatalf("len(evidence.identity) = %d, want 1", len(entries))
	}
	if entries[0]["field"] != "purl" {
		t.Fatalf("field = %v", entries[0]["field"])
	}
	if got := entries[0]["confidence"]; got != json.Number("0.8") {
		t.Fatalf("confidence = %v, want the input's 0.8 preserved", got)
	}
	methods, _ := entries[0]["methods"].([]any)
	if len(methods) != 1 {
		t.Fatalf("methods = %v", entries[0]["methods"])
	}
	method := methods[0].(map[string]any)
	if method["technique"] != "filename" || method["value"] != "slf4j-api-2.0.9.jar" {
		t.Fatalf("the wrapped method lost content: %v", method)
	}
}

func TestUpliftRejectsAnUnsupportedFloor(t *testing.T) {
	for _, floor := range []string{"1.4", "1.7", "2.0", "", "latest"} {
		doc := load(t, fixture(t, "uplift-1.4.cdx.json"))
		_, _, err := doc.Uplift(floor)
		if err == nil {
			t.Fatalf("Uplift(%q) = nil, want an error", floor)
		}
		if !strings.Contains(err.Error(), "1.5, 1.6") {
			t.Fatalf("Uplift(%q) error = %q, want it to list the supported floors", floor, err)
		}
	}
}

func TestUpliftToTheLowerSupportedFloor(t *testing.T) {
	doc := load(t, fixture(t, "uplift-1.4.cdx.json"))

	applied, _, err := doc.Uplift("1.5")
	if err != nil {
		t.Fatal(err)
	}
	if !applied || doc.SpecVersion() != "1.5" {
		t.Fatalf("Uplift(1.5) applied=%v spec=%q", applied, doc.SpecVersion())
	}
	out, err := doc.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := sbom.Validate(out, "1.5"); err != nil {
		t.Fatalf("the uplifted document is not valid 1.5: %v", err)
	}
}

func TestSchemaURL(t *testing.T) {
	if got, want := sbom.SchemaURL("1.6"), "http://cyclonedx.org/schema/bom-1.6.schema.json"; got != want {
		t.Fatalf("SchemaURL(1.6) = %q, want %q", got, want)
	}
}

func TestSupportedFloors(t *testing.T) {
	if diff := cmp.Diff([]string{"1.5", "1.6"}, sbom.SupportedFloors); diff != "" {
		t.Fatalf("SupportedFloors (-want +got):\n%s", diff)
	}
}
