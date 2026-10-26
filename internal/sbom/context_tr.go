package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/rebaze/rio/internal/buildcontext"
)

// BSI TR-03183-2 names rio writes from the build context. The gate defines
// the same names; sbom cannot import gate.
const (
	trLevelProperty = "rio:tr-03183-2:level"
	// fileComponentRef prefixes a distribution name in the bom-ref of the
	// file component rio writes for it.
	fileComponentRef = "rio:distribution:"
	// fileComponentOwner prefixes a distribution name in OwnedReferences for
	// a file component rio added.
	fileComponentOwner = "distribution-component:"
	// levelOwner is the OwnedReferences entry for a level property rio added.
	levelOwner = "level"
)

// trDistributions returns the distributions that carry the TR file fields,
// in context order.
func trDistributions(dists []buildcontext.Distribution) []buildcontext.Distribution {
	var out []buildcontext.Distribution
	for _, d := range dists {
		if d.HasTRFields() {
			out = append(out, d)
		}
	}
	return out
}

// mergeFileComponents writes one TR file component per distribution under the
// subject (metadata.component.components), so the dependency component array
// stays member for member what came in. It also writes each file's own
// empty dependencies entry, the subject's edge to it (only when the subject
// has a string bom-ref; rio never invents one) and one complete composition
// over the file refs. Entries already present are kept and not duplicated; a
// component with the same bom-ref but other content is refused, because
// distributions cannot be replaced. Each returned change lists only the
// entries rio added or changed under its target, not the whole array.
func (d *Document) mergeFileComponents(dists []buildcontext.Distribution, prior *ContextRecord) ([]ContextChange, []string, error) {
	subject := d.metadataComponent(false)
	components, ok := subject["components"].([]any)
	if _, present := subject["components"]; present && !ok {
		return nil, nil, fmt.Errorf("context distributions need the subject's components to be an array")
	}
	dependencies, ok := d.raw["dependencies"].([]any)
	if _, present := d.raw["dependencies"]; present && !ok {
		return nil, nil, fmt.Errorf("context distributions need dependencies to be an array")
	}
	compositions, ok := d.raw["compositions"].([]any)
	if _, present := d.raw["compositions"]; present && !ok {
		return nil, nil, fmt.Errorf("context distributions need compositions to be an array")
	}

	var changes []ContextChange
	owned := []string{}
	refs := make([]string, 0, len(dists))
	var added []any
	for _, dist := range dists {
		ref := fileComponentRef + dist.Name
		refs = append(refs, ref)
		want := fileComponent(dist, subject)
		existing, uses := d.componentsWithRef(ref)
		switch {
		case uses == 0:
			components = append(components, want)
			added = append(added, want)
			owned = append(owned, fileComponentOwner+dist.Name)
		case uses == 1 && existing != nil && sameJSON(existing, want):
			if prior != nil && containsString(prior.OwnedReferences, fileComponentOwner+dist.Name) {
				owned = append(owned, fileComponentOwner+dist.Name)
			}
		default:
			return nil, nil, fmt.Errorf("context distribution %q conflicts with an existing component with bom-ref %s; distributions cannot be replaced: %s", dist.Name, ref, dist.Name)
		}
	}
	if len(added) > 0 {
		subject["components"] = components
		changes = append(changes, ContextChange{Target: "/metadata/component/components", After: added})
	}

	depBefore, depAfter, dependencies, err := mergeFileDependencies(dependencies, subject, refs)
	if err != nil {
		return nil, nil, err
	}
	if depAfter != nil {
		d.raw["dependencies"] = dependencies
		changes = append(changes, ContextChange{Target: "/dependencies", Before: depBefore, After: depAfter})
	}

	covered := map[string]bool{}
	for _, raw := range compositions {
		entry, _ := raw.(map[string]any)
		if entry["aggregate"] != "complete" {
			continue
		}
		listed, _ := entry["dependencies"].([]any)
		for _, r := range listed {
			if s, ok := r.(string); ok {
				covered[s] = true
			}
		}
	}
	var uncovered []any
	for _, ref := range refs {
		if !covered[ref] {
			uncovered = append(uncovered, ref)
		}
	}
	if len(uncovered) > 0 {
		composition := map[string]any{"aggregate": "complete", "dependencies": uncovered}
		d.raw["compositions"] = append(compositions, composition)
		changes = append(changes, ContextChange{Target: "/compositions", After: []any{composition}})
	}
	return changes, owned, nil
}

// mergeFileDependencies gives each file ref its own dependencies entry, empty
// unless one exists, and adds the refs to the subject's dependsOn. It returns
// the touched entries before and after, and after is nil when nothing changed.
func mergeFileDependencies(deps []any, subject map[string]any, refs []string) (before, after any, next []any, err error) {
	next = append([]any{}, deps...)
	entries := map[string]bool{}
	for _, raw := range next {
		if entry, ok := raw.(map[string]any); ok {
			if ref, ok := entry["ref"].(string); ok {
				entries[ref] = true
			}
		}
	}
	var touchedBefore, touchedAfter []any
	if subjectRef, ok := subject["bom-ref"].(string); ok && subjectRef != "" {
		index := -1
		for i, raw := range next {
			if entry, ok := raw.(map[string]any); ok && entry["ref"] == subjectRef {
				index = i
				break
			}
		}
		if index < 0 {
			dependsOn := make([]any, 0, len(refs))
			for _, ref := range refs {
				dependsOn = append(dependsOn, ref)
			}
			entry := map[string]any{"ref": subjectRef, "dependsOn": dependsOn}
			next = append(next, entry)
			touchedAfter = append(touchedAfter, entry)
		} else {
			old := next[index].(map[string]any)
			dependsOn, ok := old["dependsOn"].([]any)
			if _, present := old["dependsOn"]; present && !ok {
				return nil, nil, nil, fmt.Errorf("context distributions need the subject's dependsOn to be an array")
			}
			listed := map[string]bool{}
			for _, r := range dependsOn {
				if s, ok := r.(string); ok {
					listed[s] = true
				}
			}
			grown := append([]any{}, dependsOn...)
			for _, ref := range refs {
				if !listed[ref] {
					grown = append(grown, ref)
				}
			}
			if len(grown) > len(dependsOn) {
				entry := map[string]any{}
				for k, v := range old {
					entry[k] = v
				}
				entry["dependsOn"] = grown
				next[index] = entry
				touchedBefore = append(touchedBefore, old)
				touchedAfter = append(touchedAfter, entry)
			}
		}
	}
	for _, ref := range refs {
		if !entries[ref] {
			entry := map[string]any{"ref": ref, "dependsOn": []any{}}
			next = append(next, entry)
			touchedAfter = append(touchedAfter, entry)
		}
	}
	if len(touchedAfter) == 0 {
		return nil, nil, deps, nil
	}
	if len(touchedBefore) > 0 {
		before = touchedBefore
	}
	return before, touchedAfter, next, nil
}

// fileComponent is the TR file component for one distribution. Version,
// creator and licences come from the subject, when it has them.
func fileComponent(dist buildcontext.Distribution, subject map[string]any) map[string]any {
	url := dist.URL
	if url == "" {
		url = distributionNameURL(dist.Name)
	}
	choose := func(b *bool, yes, no string) string {
		if *b {
			return yes
		}
		return no
	}
	c := map[string]any{
		"type":    "file",
		"bom-ref": fileComponentRef + dist.Name,
		"name":    dist.Name,
		"properties": []any{
			map[string]any{"name": "bsi:component:filename", "value": dist.Name},
			map[string]any{"name": "bsi:component:executable", "value": choose(dist.Executable, "executable", "non-executable")},
			map[string]any{"name": "bsi:component:archive", "value": choose(dist.Archive, "archive", "no archive")},
			map[string]any{"name": "bsi:component:structured", "value": choose(dist.Structured, "structured", "unstructured")},
		},
		"externalReferences": []any{map[string]any{"type": "distribution", "url": url, "hashes": []any{
			map[string]any{"alg": "SHA-256", "content": dist.SHA256},
			map[string]any{"alg": "SHA-512", "content": dist.SHA512},
		}}},
	}
	if version, ok := subject["version"].(string); ok && version != "" {
		c["version"] = version
	}
	if manufacturer, ok := subject["manufacturer"].(map[string]any); ok {
		c["manufacturer"] = copyWithoutBOMRefs(manufacturer)
	}
	if licenses, ok := subject["licenses"].([]any); ok {
		c["licenses"] = copyWithoutBOMRefs(licenses)
	}
	return c
}

// copyWithoutBOMRefs deep-copies v, dropping every bom-ref: a bom-ref must be
// unique in the BOM, and the subject keeps its own.
func copyWithoutBOMRefs(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, child := range x {
			if k != "bom-ref" {
				out[k] = copyWithoutBOMRefs(child)
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, child := range x {
			out[i] = copyWithoutBOMRefs(child)
		}
		return out
	}
	return v
}

// componentsWithRef counts the components anywhere in the document, the
// subject and its nested components included, that use ref as their bom-ref,
// and returns the one directly under the subject if there is one.
func (d *Document) componentsWithRef(ref string) (underSubject map[string]any, uses int) {
	count := func(_ string, obj map[string]any) {
		if obj != nil && obj["bom-ref"] == ref {
			uses++
		}
	}
	if subject := d.metadataComponent(false); subject != nil {
		if subject["bom-ref"] == ref {
			uses++
		}
		list, _ := subject["components"].([]any)
		for _, raw := range list {
			if obj, ok := raw.(map[string]any); ok && obj["bom-ref"] == ref {
				underSubject = obj
			}
		}
		visitComponents(subject["components"], "metadata.component.components", count)
	}
	visitComponents(d.raw["components"], "components", count)
	return underSubject, uses
}

func sameJSON(a, b any) bool {
	x, errA := json.Marshal(a)
	y, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(x, y)
}

// mergeLevel writes the subject's level property. An existing property with
// the same value is kept; one with another value cannot be replaced.
func mergeLevel(subject map[string]any, level string, prior *ContextRecord) (before, after any, owned, changed bool, err error) {
	before = subject["properties"]
	props, ok := before.([]any)
	if before != nil && !ok {
		return nil, nil, false, false, fmt.Errorf("context level needs the subject's properties to be an array")
	}
	found := false
	for _, raw := range props {
		prop, _ := raw.(map[string]any)
		if prop["name"] != trLevelProperty {
			continue
		}
		value, _ := prop["value"].(string)
		if value != level {
			return nil, nil, false, false, levelConflict(level, value)
		}
		found = true
	}
	if found {
		owned = prior != nil && containsString(prior.OwnedReferences, levelOwner)
		return before, before, owned, false, nil
	}
	next := append(append([]any{}, props...), map[string]any{"name": trLevelProperty, "value": level})
	subject["properties"] = next
	return before, next, true, true, nil
}

func levelConflict(level, existing string) error {
	return fmt.Errorf("context level %q conflicts with the SBOM's %s %q; the level cannot be replaced", level, trLevelProperty, existing)
}
