package sbom_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/sbom"
)

// The embedded SPDX enum is licence IDs in case-insensitive order followed by
// exception IDs in the same order, so it splits where that order breaks. A
// schema update with another layout must fail here rather than silently
// mixing exceptions into licences.
func TestSPDXListLayout(t *testing.T) {
	data, err := os.ReadFile("schemas/spdx.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Enum []string `json:"enum"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	var breaks []int
	for i := 1; i < len(schema.Enum); i++ {
		if strings.ToLower(schema.Enum[i]) < strings.ToLower(schema.Enum[i-1]) {
			breaks = append(breaks, i)
		}
	}
	if len(breaks) != 1 {
		t.Fatalf("the SPDX enum breaks case-insensitive order at %v, want exactly one break between licences and exceptions", breaks)
	}
	licences, exceptions := 0, 0
	for _, id := range schema.Enum {
		l, e := sbom.KnownSPDXLicence(id), sbom.KnownSPDXException(id)
		if l == e {
			t.Errorf("%q: licence %v, exception %v; want exactly one", id, l, e)
		}
		if l {
			licences++
		} else {
			exceptions++
		}
	}
	if licences != breaks[0] || exceptions != len(schema.Enum)-breaks[0] {
		t.Errorf("licences %d, exceptions %d; want %d and %d", licences, exceptions, breaks[0], len(schema.Enum)-breaks[0])
	}
}

func TestSPDXLicencesAndExceptions(t *testing.T) {
	cases := []struct {
		id                 string
		licence, exception bool
	}{
		{"MIT", true, false},
		{"Apache-2.0", true, false},
		{"0BSD", true, false},
		// A deprecated licence ID that names an exception is still a licence.
		{"GPL-2.0-with-classpath-exception", true, false},
		{"LLVM-exception", false, true},
		{"Classpath-exception-2.0", false, true},
		{"389-exception", false, true},
		{"NotALicence-1.0", false, false},
		{"mit", false, false},
	}
	for _, tc := range cases {
		if got := sbom.KnownSPDXLicence(tc.id); got != tc.licence {
			t.Errorf("KnownSPDXLicence(%q) = %v, want %v", tc.id, got, tc.licence)
		}
		if got := sbom.KnownSPDXException(tc.id); got != tc.exception {
			t.Errorf("KnownSPDXException(%q) = %v, want %v", tc.id, got, tc.exception)
		}
	}
}
