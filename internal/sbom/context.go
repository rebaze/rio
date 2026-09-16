package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/rebaze/rio/internal/buildcontext"
)

const contextProperty = PropertyPrefix + "context"

// ContextRecord is the active producer assertion, shared by the SBOM property,
// index artifact, and statement predicate.
type ContextRecord struct {
	Version   int                   `json:"version"`
	File      buildcontext.FileRef  `json:"file"`
	Selector  string                `json:"selector"`
	Effective buildcontext.Artifact `json:"effective"`
	Defaulted []string              `json:"defaulted"`
	Changes   []ContextChange       `json:"changes"`
	Assertion string                `json:"assertion"`
}

type ContextChange struct {
	Field    string `json:"field"`
	Target   string `json:"target"`
	Before   any    `json:"before"`
	After    any    `json:"after"`
	Selector string `json:"selector"`
	Override bool   `json:"override"`
}

// ApplyContext atomically attaches one resolved snapshot to the product
// subject. On an error the receiver retains its exact pre-call bytes.
func (d *Document) ApplyContext(cfg *buildcontext.Resolved) (*ContextRecord, error) {
	if cfg == nil {
		return nil, nil
	}
	working, err := d.cloneForMetadata()
	if err != nil {
		return nil, err
	}
	if working.metadataComponent(false) == nil {
		return nil, fmt.Errorf("context requires metadata.component subject")
	}
	prior, err := working.priorContext(cfg.Artifact.ID)
	if err != nil {
		return nil, err
	}
	rec := &ContextRecord{Version: 1, File: cfg.File, Selector: cfg.Selector, Effective: cfg.Artifact, Defaulted: append([]string{}, cfg.Defaulted...), Changes: []ContextChange{}, Assertion: "producer"}
	replacement := map[string]bool{}
	for _, field := range cfg.Replace {
		replacement[field] = true
	}
	current := effectiveLeaves(cfg.Artifact)
	old := map[string]string{}
	if prior != nil {
		old = effectiveLeaves(prior.Effective)
	}
	selectors := map[string]string{}
	for _, field := range cfg.Fields {
		selectors[field.Name] = field.Selector
	}
	names := map[string]bool{}
	for name := range current {
		names[name] = true
	}
	for name := range old {
		names[name] = true
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	for _, name := range ordered {
		before, bok := old[name]
		after, aok := current[name]
		if bok && aok && before == after {
			continue
		}
		if bok && (name == "lifecycle" || !replacement[name]) {
			return nil, fmt.Errorf("context %s conflicts with prior owned assertion; explicitly list %s in context.replace", name, name)
		}
		var b, a any
		if bok {
			b = before
		}
		if aok {
			a = after
		}
		selector := selectors[name]
		if selector == "" {
			selector = cfg.Selector
		}
		rec.Changes = append(rec.Changes, ContextChange{Field: name, Target: "context:/" + strings.ReplaceAll(name, ".", "/"), Before: b, After: a, Selector: selector, Override: bok})
	}
	for _, native := range []struct {
		name, kind string
	}{{"source.repository", "vcs"}, {"build.url", "build-system"}} {
		value, ok := current[native.name]
		if !ok {
			continue
		}
		parent := working.metadataComponent(false)
		if parent == nil {
			return nil, fmt.Errorf("context %s requires metadata.component subject", native.name)
		}
		before, after, changed, err := mergeReference(parent, native.kind, value, replacement[native.name])
		if err != nil {
			return nil, fmt.Errorf("context %s conflicts with existing %s external reference; explicitly list %s in context.replace", native.name, native.kind, native.name)
		}
		if changed {
			override := referenceConflict(before, native.kind, value)
			rec.Changes = append(rec.Changes, ContextChange{Field: native.name, Target: "/metadata/component/externalReferences", Before: before, After: after, Selector: selectors[native.name], Override: override})
		}
	}
	if phase, ok := current["lifecycle"]; ok {
		before, after, changed, err := working.mergeLifecycle(phase)
		if err != nil {
			return nil, err
		}
		if changed {
			rec.Changes = append(rec.Changes, ContextChange{Field: "lifecycle", Target: "/metadata/lifecycles", Before: before, After: after, Selector: selectors["lifecycle"]})
		}
	}
	encoded, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	working.replaceContextProperty(string(encoded))
	d.raw = working.raw
	d.indexComponents()
	return rec, nil
}

func (d *Document) cloneForMetadata() (*Document, error) {
	data, err := json.Marshal(d.raw)
	if err != nil {
		return nil, err
	}
	working := *d
	working.raw = nil
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&working.raw); err != nil {
		return nil, err
	}
	working.indexComponents()
	return &working, nil
}

func effectiveLeaves(a buildcontext.Artifact) map[string]string {
	out := map[string]string{}
	data, _ := json.Marshal(a)
	var root map[string]any
	_ = json.Unmarshal(data, &root)
	var walk func(string, any)
	walk = func(prefix string, value any) {
		switch v := value.(type) {
		case string:
			if prefix != "id" && prefix != "sbom.sha256" {
				out[prefix] = v
			}
		case map[string]any:
			for k, child := range v {
				key := k
				if prefix != "" {
					key = prefix + "." + k
				}
				walk(key, child)
			}
		}
	}
	walk("", root)
	return out
}

func (d *Document) priorContext(id string) (*ContextRecord, error) {
	meta := d.metadata(false)
	if meta == nil {
		return nil, nil
	}
	props, _ := meta["properties"].([]any)
	var prior *ContextRecord
	for _, raw := range props {
		prop, _ := raw.(map[string]any)
		if prop["name"] != contextProperty {
			continue
		}
		value, ok := prop["value"].(string)
		if !ok {
			return nil, fmt.Errorf("malformed prior %s property", contextProperty)
		}
		dec := json.NewDecoder(strings.NewReader(value))
		dec.DisallowUnknownFields()
		var record struct {
			Version   int                  `json:"version"`
			File      buildcontext.FileRef `json:"file"`
			Selector  string               `json:"selector"`
			Effective json.RawMessage      `json:"effective"`
			Defaulted []string             `json:"defaulted"`
			Changes   []ContextChange      `json:"changes"`
			Assertion string               `json:"assertion"`
		}
		if err := dec.Decode(&record); err != nil {
			return nil, fmt.Errorf("malformed prior %s property: %w", contextProperty, err)
		}
		if _, err := dec.Token(); err != io.EOF {
			return nil, fmt.Errorf("malformed prior %s property: trailing data", contextProperty)
		}
		effective, err := buildcontext.ParseEffective(record.Effective)
		if err != nil {
			return nil, fmt.Errorf("malformed prior %s effective: %w", contextProperty, err)
		}
		if record.Version != 1 || record.Assertion != "producer" || record.File.Path == "" || !contextDigest(record.File.SHA256) || !contextSelector(record.Selector) || record.Defaulted == nil || record.Changes == nil || effective.ID != id || !validPriorDefaults(record.Defaulted, effective) {
			return nil, fmt.Errorf("unsupported or malformed prior %s property", contextProperty)
		}
		current := &ContextRecord{Version: record.Version, File: record.File, Selector: record.Selector, Effective: effective, Defaulted: record.Defaulted, Changes: record.Changes, Assertion: record.Assertion}
		if prior != nil && !reflect.DeepEqual(prior, current) {
			return nil, fmt.Errorf("contradictory prior %s properties", contextProperty)
		}
		prior = current
	}
	return prior, nil
}

func contextDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func contextSelector(s string) bool {
	if !strings.HasPrefix(s, "/artifacts/") {
		return false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "/artifacts/"))
	return err == nil && n >= 0 && s == fmt.Sprintf("/artifacts/%d", n)
}

func validPriorDefaults(defaulted []string, effective buildcontext.Artifact) bool {
	if len(defaulted) == 0 {
		return true
	}
	return len(defaulted) == 1 && defaulted[0] == "source.workspace" && effective.Source != nil && effective.Source.Workspace != nil && *effective.Source.Workspace == "unknown"
}

func (d *Document) replaceContextProperty(value string) {
	meta := d.metadata(true)
	props, _ := meta["properties"].([]any)
	next := make([]any, 0, len(props)+1)
	for _, raw := range props {
		prop, _ := raw.(map[string]any)
		if prop["name"] != contextProperty {
			next = append(next, raw)
		}
	}
	next = append(next, map[string]any{"name": contextProperty, "value": value})
	meta["properties"] = next
}

func referenceConflict(before any, kind, url string) bool {
	refs, _ := before.([]any)
	for _, raw := range refs {
		ref, _ := raw.(map[string]any)
		if ref["type"] == kind && ref["url"] != url {
			return true
		}
	}
	return false
}

func (d *Document) mergeLifecycle(phase string) (before, after any, changed bool, err error) {
	meta := d.metadata(true)
	before = meta["lifecycles"]
	list, _ := before.([]any)
	if len(list) == 0 {
		after = []any{map[string]any{"phase": phase}}
		meta["lifecycles"] = after
		return before, after, true, nil
	}
	known, match := false, false
	for _, raw := range list {
		entry, _ := raw.(map[string]any)
		p, _ := entry["phase"].(string)
		if p != "" {
			known = true
			if p == phase {
				match = true
			}
		}
	}
	if known && !match {
		return nil, nil, false, fmt.Errorf("context lifecycle conflicts with existing /metadata/lifecycles")
	}
	return before, before, false, nil
}
