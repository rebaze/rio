package sbom

import "sort"

// IntegrityFinding is a dependency reference that resolves to no bom-ref in
// the document.
type IntegrityFinding struct {
	// Ref is the dangling identifier.
	Ref string `json:"ref"`
	// Kind is "dependency" for a dependencies[].ref, "dependsOn" for an entry
	// inside a dependsOn array.
	Kind string `json:"kind"`
	// From is the dependencies[].ref that carried the dangling dependsOn
	// entry. Empty when Kind is "dependency".
	From string `json:"from,omitempty"`
}

// IntegrityFindings reports dependency references that resolve to no
// component.
//
// The JSON schema does not check that dependencies[].ref and dependsOn entries
// resolve to a bom-ref, so this is checked separately. Findings are reported
// and never repaired: cyclonedx-maven-plugin 2.7.9 emits one on a plain Tycho
// build, and failing over a generator's bug would make rio unusable on the
// estate it was built for (§5 step 2b).
func (d *Document) IntegrityFindings() []IntegrityFinding {
	// Walk the whole components tree, not just the top level: a nested
	// component carries a bom-ref that dependencies may legitimately target.
	known := map[string]bool{}
	collectNestedRefs(d.raw["components"], known)
	collectNestedRefs(d.raw["services"], known)
	if comp := d.metadataComponent(false); comp != nil {
		if ref := stringField(comp, "bom-ref"); ref != "" {
			known[ref] = true
		}
	}

	deps, _ := d.raw["dependencies"].([]any)
	seen := map[IntegrityFinding]bool{}
	var findings []IntegrityFinding

	add := func(f IntegrityFinding) {
		if f.Ref == "" || known[f.Ref] || seen[f] {
			return
		}
		seen[f] = true
		findings = append(findings, f)
	}

	for _, entry := range deps {
		obj, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		ref := stringField(obj, "ref")
		add(IntegrityFinding{Ref: ref, Kind: "dependency"})

		dependsOn, _ := obj["dependsOn"].([]any)
		for _, target := range dependsOn {
			s, _ := target.(string)
			add(IntegrityFinding{Ref: s, Kind: "dependsOn", From: ref})
		}
	}

	// Stable order so index.json is byte identical across runs (§7).
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Ref != findings[j].Ref {
			return findings[i].Ref < findings[j].Ref
		}
		if findings[i].Kind != findings[j].Kind {
			return findings[i].Kind < findings[j].Kind
		}
		return findings[i].From < findings[j].From
	})
	return findings
}

// collectNestedRefs walks an arbitrary subtree collecting every bom-ref it
// declares.
func collectNestedRefs(node any, into map[string]bool) {
	switch v := node.(type) {
	case []any:
		for _, e := range v {
			collectNestedRefs(e, into)
		}
	case map[string]any:
		if ref := stringField(v, "bom-ref"); ref != "" {
			into[ref] = true
		}
		for _, e := range v {
			collectNestedRefs(e, into)
		}
	}
}
