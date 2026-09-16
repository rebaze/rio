package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"

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
		if bok && name == "lifecycle" {
			return nil, fmt.Errorf("context lifecycle prior owned assertion cannot be changed or removed")
		}
		if bok && !replacement[name] {
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
		record, err := parsePriorContext(value, id)
		if err != nil {
			return nil, fmt.Errorf("malformed prior %s property: %w", contextProperty, err)
		}
		if prior != nil && !reflect.DeepEqual(prior, record) {
			return nil, fmt.Errorf("contradictory prior %s properties", contextProperty)
		}
		prior = record
	}
	return prior, nil
}

// parsePriorContext checks presence and type before decoding values. Ordinary
// encoding/json struct decoding cannot detect duplicate keys or distinguish a
// missing before/after member from an intentional JSON null.
func parsePriorContext(value, id string) (*ContextRecord, error) {
	raw, err := buildcontext.DecodeStrict([]byte(value))
	if err != nil {
		return nil, err
	}
	root, err := recordObject(raw, "record", "version", "file", "selector", "effective", "defaulted", "changes", "assertion")
	if err != nil {
		return nil, err
	}
	version, ok := root["version"].(json.Number)
	if !ok || version.String() != "1" {
		return nil, fmt.Errorf("unsupported version")
	}
	file, err := recordObject(root["file"], "file", "path", "sha256")
	if err != nil {
		return nil, err
	}
	path, err := recordString(file["path"], "file.path")
	if err != nil {
		return nil, err
	}
	if filepath.IsAbs(path) {
		return nil, fmt.Errorf("file.path must be manifest-relative")
	}
	digest, err := recordString(file["sha256"], "file.sha256")
	if err != nil {
		return nil, err
	}
	if !contextDigest(digest) {
		return nil, fmt.Errorf("file.sha256 must be a lowercase SHA-256 digest")
	}
	selector, err := recordString(root["selector"], "selector")
	if err != nil {
		return nil, err
	}
	if !contextSelector(selector) {
		return nil, fmt.Errorf("invalid selector")
	}
	assertion, err := recordString(root["assertion"], "assertion")
	if err != nil {
		return nil, err
	}
	if assertion != "producer" {
		return nil, fmt.Errorf("unsupported assertion")
	}
	effectiveJSON, err := json.Marshal(root["effective"])
	if err != nil {
		return nil, err
	}
	effective, err := buildcontext.ParseEffective(effectiveJSON)
	if err != nil {
		return nil, fmt.Errorf("effective: %w", err)
	}
	if effective.ID != id {
		return nil, fmt.Errorf("effective.id does not match artifact")
	}
	if effective.Source != nil && effective.Source.Workspace == nil {
		return nil, fmt.Errorf("effective.source.workspace is missing from prior snapshot")
	}
	rawDefaulted, ok := root["defaulted"].([]any)
	if !ok {
		return nil, fmt.Errorf("defaulted must be an array")
	}
	defaulted := make([]string, 0, len(rawDefaulted))
	for i, item := range rawDefaulted {
		s, err := recordString(item, fmt.Sprintf("defaulted[%d]", i))
		if err != nil {
			return nil, err
		}
		defaulted = append(defaulted, s)
	}
	if !validPriorDefaults(defaulted, effective) {
		return nil, fmt.Errorf("invalid defaulted fields")
	}
	rawChanges, ok := root["changes"].([]any)
	if !ok {
		return nil, fmt.Errorf("changes must be an array")
	}
	changes := make([]ContextChange, 0, len(rawChanges))
	for i, item := range rawChanges {
		label := fmt.Sprintf("changes[%d]", i)
		change, err := recordObject(item, label, "field", "target", "before", "after", "selector", "override")
		if err != nil {
			return nil, err
		}
		field, err := recordString(change["field"], label+".field")
		if err != nil {
			return nil, err
		}
		target, err := recordString(change["target"], label+".target")
		if err != nil {
			return nil, err
		}
		source, err := recordString(change["selector"], label+".selector")
		if err != nil {
			return nil, err
		}
		override, ok := change["override"].(bool)
		if !ok {
			return nil, fmt.Errorf("%s.override must be a boolean", label)
		}
		if (source != selector && !strings.HasPrefix(source, selector+"/")) || !validContextChange(field, target, change["before"], change["after"]) {
			return nil, fmt.Errorf("%s has invalid target or selector", label)
		}
		changes = append(changes, ContextChange{Field: field, Target: target, Before: change["before"], After: change["after"], Selector: source, Override: override})
	}
	return &ContextRecord{Version: 1, File: buildcontext.FileRef{Path: path, SHA256: digest}, Selector: selector, Effective: effective, Defaulted: defaulted, Changes: changes, Assertion: assertion}, nil
}

func validContextChange(field, target string, before, after any) bool {
	if err := buildcontext.ValidateBinding(&buildcontext.Binding{File: "prior", Require: []string{field}}); err != nil {
		return false
	}
	logical := "context:/" + strings.ReplaceAll(field, ".", "/")
	if target == logical {
		return optionalStringClaim(before) && optionalStringClaim(after)
	}
	if target == "/metadata/component/externalReferences" && (field == "source.repository" || field == "build.url") {
		return optionalArrayClaim(before) && optionalArrayClaim(after)
	}
	if target == "/metadata/lifecycles" && field == "lifecycle" {
		return optionalArrayClaim(before) && optionalArrayClaim(after)
	}
	return false
}

func optionalStringClaim(v any) bool {
	if v == nil {
		return true
	}
	_, ok := v.(string)
	return ok
}
func optionalArrayClaim(v any) bool {
	if v == nil {
		return true
	}
	_, ok := v.([]any)
	return ok
}

func recordObject(value any, label string, keys ...string) (map[string]any, error) {
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
		if _, exists := m[key]; !exists {
			return nil, fmt.Errorf("%s.%s is required", label, key)
		}
	}
	for key := range m {
		if !allowed[key] {
			return nil, fmt.Errorf("%s has unknown key %q", label, key)
		}
	}
	return m, nil
}

func recordString(value any, label string) (string, error) {
	s, ok := value.(string)
	if !ok || strings.TrimSpace(s) == "" || strings.TrimSpace(s) != s {
		return "", fmt.Errorf("%s must be a nonblank string", label)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("%s must not contain controls", label)
		}
	}
	return s, nil
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
