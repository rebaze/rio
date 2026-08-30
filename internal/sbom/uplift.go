package sbom

import (
	"fmt"
	"strconv"
	"strings"
)

// SupportedFloors are the values output.specVersionFloor accepts (§2).
var SupportedFloors = []string{"1.5", "1.6"}

// Uplift raises the document to floor when it declares something lower, and
// reports whether it did.
//
// Uplift is deliberately small: CycloneDX 1.4 through 1.6 are additive, so a
// construct valid at 1.4 stays valid at 1.6. Only what is genuinely invalid at
// the target is migrated; everything deprecated but valid is left as found
// (§5 step 2).
func (d *Document) Uplift(floor string) (applied bool, from string, err error) {
	from = d.specVersion

	if !isSupportedFloor(floor) {
		return false, from, fmt.Errorf("unsupported spec version floor %q, want one of %s",
			floor, strings.Join(SupportedFloors, ", "))
	}
	if compareSpecVersions(d.specVersion, floor) >= 0 {
		return false, from, nil
	}

	d.raw["specVersion"] = floor
	d.specVersion = floor

	// Only rewrite $schema when the input carried one. Adding one the
	// generator did not write would be a change rio was not asked to make.
	if _, ok := d.raw["$schema"].(string); ok {
		d.raw["$schema"] = SchemaURL(floor)
	}

	d.wrapIdentityEvidence()

	return true, from, nil
}

// wrapIdentityEvidence rewrites evidence.identity from the 1.5 object form to
// the 1.6 array form, preserving its content.
//
// 1.6 accepts both shapes, so this is not strictly required by the schema. It
// is required by §4.3b: rio appends identity evidence in the array form, and a
// document must not end up carrying both shapes in different components.
func (d *Document) wrapIdentityEvidence() {
	for _, raw := range d.componentRaw {
		evidence, ok := raw["evidence"].(map[string]any)
		if !ok {
			continue
		}
		if identity, ok := evidence["identity"].(map[string]any); ok {
			evidence["identity"] = []any{identity}
		}
	}
}

// SchemaURL is the canonical $schema value for a spec version.
func SchemaURL(specVersion string) string {
	return "http://cyclonedx.org/schema/bom-" + specVersion + ".schema.json"
}

func isSupportedFloor(v string) bool {
	for _, f := range SupportedFloors {
		if f == v {
			return true
		}
	}
	return false
}

// compareSpecVersions orders dotted numeric spec versions. A segment that does
// not parse sorts after every numeric one, so an unrecognised version is
// treated as newer and passes through rather than being uplifted (§3).
func compareSpecVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		av, aok := segment(as, i)
		bv, bok := segment(bs, i)
		switch {
		case !aok && !bok:
			continue
		case !aok:
			return 1
		case !bok:
			return -1
		case av != bv:
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

func segment(parts []string, i int) (int, bool) {
	if i >= len(parts) {
		return 0, true
	}
	v, err := strconv.Atoi(parts[i])
	if err != nil {
		return 0, false
	}
	return v, true
}
