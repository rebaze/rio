// Package sbom owns all CycloneDX document IO. Nothing outside this package
// decodes or encodes CycloneDX (§9d).
//
// A Document holds two views decoded from the same bytes:
//
//   - raw, a map[string]any decoded with UseNumber(). Every write lands here
//     and this is what gets serialized, so fields no library models survive
//     the round trip (§8).
//   - typed, a cyclonedx-go BOM decoded from those same bytes. It is a
//     snapshot of the INPUT, used for spec version handling and to confirm the
//     document decodes as CycloneDX at all. It is never re-encoded, and it is
//     never refreshed after a write.
//
// components[i] refers to the same component in both views, so the slice index
// is the join key between them.
//
// Every accessor for a field rio may rewrite reads the raw tree, not the
// snapshot. §5 runs the transforms and then the gate over one Document, and a
// second transform reads what the first one wrote, so a stale snapshot would
// hand both of them the purl the document no longer carries.
package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// PropertyPrefix namespaces every property rio writes.
const PropertyPrefix = "rebaze:normalize:"

// Document is a loaded CycloneDX JSON document.
type Document struct {
	raw   map[string]any
	typed *cdx.BOM

	// typedErr records why the typed decode failed, if it did. A spec version
	// newer than cyclonedx-go models is the expected cause and is not fatal:
	// the raw tree remains the source of truth (§3).
	typedErr error

	specVersion string

	// Properties rio appends, held back until Finalize so they can be sorted
	// by name then value independently of what the generator already wrote (§7).
	pendingMeta  []Property
	pendingComp  map[int][]Property
	componentRaw []map[string]any
}

// Property is a CycloneDX name/value property.
type Property struct {
	Name  string
	Value string
}

// Load decodes CycloneDX JSON. It fails only when the bytes are not a
// CycloneDX JSON document at all; an unrecognised spec version is not an error.
func Load(data []byte) (*Document, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing content after the JSON document")
	}

	format, _ := raw["bomFormat"].(string)
	if format != "CycloneDX" {
		if format == "" {
			return nil, fmt.Errorf(`not a CycloneDX document: no "bomFormat" field`)
		}
		return nil, fmt.Errorf("not a CycloneDX document: bomFormat is %q, want %q", format, "CycloneDX")
	}

	specVersion, ok := raw["specVersion"].(string)
	if !ok || specVersion == "" {
		return nil, fmt.Errorf(`not a CycloneDX document: no "specVersion" field`)
	}

	doc := &Document{
		raw:         raw,
		specVersion: specVersion,
		pendingComp: map[int][]Property{},
	}
	doc.indexComponents()

	// Typed decode from the same bytes. Failure is recorded, not returned:
	// a document above the versions cyclonedx-go models still passes through.
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		doc.typedErr = err
	} else {
		doc.typed = &bom
	}

	return doc, nil
}

func (d *Document) indexComponents() {
	d.componentRaw = nil
	list, ok := d.raw["components"].([]any)
	if !ok {
		return
	}
	for _, entry := range list {
		obj, ok := entry.(map[string]any)
		if !ok {
			// A non-object in components is schema-invalid; validation reports
			// it. Keep a placeholder so indexes stay aligned with the raw array.
			obj = nil
		}
		d.componentRaw = append(d.componentRaw, obj)
	}
}

// SpecVersion returns the document's declared spec version.
func (d *Document) SpecVersion() string { return d.specVersion }

// TypedDecodeError reports why the typed cyclonedx-go view is unavailable, or
// nil when it decoded cleanly.
func (d *Document) TypedDecodeError() error { return d.typedErr }

// ComponentCount returns the number of top-level components.
//
// v1 operates on the top-level components array only. That is what the join by
// index in §8 addresses and what cyclonedx-maven-plugin emits; nested
// components are carried through untouched.
func (d *Document) ComponentCount() int { return len(d.componentRaw) }

// Component returns a view of the component at index i.
func (d *Document) Component(i int) *Component {
	if i < 0 || i >= len(d.componentRaw) {
		return nil
	}
	c := &Component{Index: i, doc: d, raw: d.componentRaw[i]}
	if d.typed != nil && d.typed.Components != nil && i < len(*d.typed.Components) {
		c.typed = &(*d.typed.Components)[i]
	}
	return c
}

// Components returns views of every top-level component, in document order.
func (d *Document) Components() []*Component {
	out := make([]*Component, 0, len(d.componentRaw))
	for i := range d.componentRaw {
		out = append(out, d.Component(i))
	}
	return out
}

// Fingerprint is the identity of the component array: its length and the
// bom-ref of every member, in order. The pipeline asserts it is unchanged
// across each transform (§5 step 3).
func (d *Document) Fingerprint() []string {
	out := make([]string, 0, len(d.componentRaw))
	for i := range d.componentRaw {
		out = append(out, stringField(d.componentRaw[i], "bom-ref")+"\x00"+
			stringField(d.componentRaw[i], "name")+"\x00"+
			stringField(d.componentRaw[i], "version"))
	}
	return out
}

// Subject returns metadata.component's name and version.
func (d *Document) Subject() (name, version string) {
	comp := d.metadataComponent(false)
	if comp == nil {
		return "", ""
	}
	return stringField(comp, "name"), stringField(comp, "version")
}

// SetSubject overrides metadata.component's name and version, returning the
// values it replaced (§4.3d).
func (d *Document) SetSubject(name, version string) (oldName, oldVersion string) {
	comp := d.metadataComponent(true)
	oldName, oldVersion = stringField(comp, "name"), stringField(comp, "version")
	comp["name"] = name
	comp["version"] = version
	return oldName, oldVersion
}

func (d *Document) metadata(create bool) map[string]any {
	meta, ok := d.raw["metadata"].(map[string]any)
	if !ok {
		if !create {
			return nil
		}
		meta = map[string]any{}
		d.raw["metadata"] = meta
	}
	return meta
}

func (d *Document) metadataComponent(create bool) map[string]any {
	meta := d.metadata(create)
	if meta == nil {
		return nil
	}
	comp, ok := meta["component"].(map[string]any)
	if !ok {
		if !create {
			return nil
		}
		comp = map[string]any{}
		meta["component"] = comp
	}
	return comp
}

// AddMetadataProperty queues a property for metadata.properties. Queued
// properties are sorted by name then value and appended by Finalize (§7).
func (d *Document) AddMetadataProperty(name, value string) {
	d.pendingMeta = append(d.pendingMeta, Property{Name: name, Value: value})
}

// AddTool records rio in metadata.tools, using whichever shape the document
// already carries. The deprecated flat array form is extended in place rather
// than converted (§4.3c).
func (d *Document) AddTool(version string) {
	meta := d.metadata(true)

	switch tools := meta["tools"].(type) {
	case []any:
		meta["tools"] = append(tools, map[string]any{
			"vendor":  "rebaze",
			"name":    "rio",
			"version": version,
		})
	case map[string]any:
		comps, _ := tools["components"].([]any)
		tools["components"] = append(comps, map[string]any{
			"type":    "application",
			"group":   "rebaze",
			"name":    "rio",
			"version": version,
		})
		meta["tools"] = tools
	default:
		// Absent. 1.5 introduced the object form and it is the shape every
		// output of rio can carry, since the floor is at least 1.5.
		if compareSpecVersions(d.specVersion, "1.5") >= 0 {
			meta["tools"] = map[string]any{
				"components": []any{map[string]any{
					"type":    "application",
					"group":   "rebaze",
					"name":    "rio",
					"version": version,
				}},
			}
		} else {
			meta["tools"] = []any{map[string]any{
				"vendor":  "rebaze",
				"name":    "rio",
				"version": version,
			}}
		}
	}
}

// Finalize appends every queued property. Call it once, after all transforms
// and before serializing.
func (d *Document) Finalize() {
	if len(d.pendingMeta) > 0 {
		meta := d.metadata(true)
		meta["properties"] = appendProperties(meta["properties"], d.pendingMeta)
		d.pendingMeta = nil
	}
	for i, props := range d.pendingComp {
		raw := d.componentRaw[i]
		if raw == nil {
			continue
		}
		raw["properties"] = appendProperties(raw["properties"], props)
	}
	d.pendingComp = map[int][]Property{}
}

// appendProperties sorts additions by name then value and appends them to an
// existing properties array, whose own order is preserved (§7).
func appendProperties(existing any, additions []Property) []any {
	sorted := make([]Property, len(additions))
	copy(sorted, additions)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].Value < sorted[j].Value
	})

	list, _ := existing.([]any)
	for _, p := range sorted {
		list = append(list, map[string]any{"name": p.Name, "value": p.Value})
	}
	return list
}

// Bytes serializes the document. Map keys are sorted by encoding/json, HTML
// escaping is off so purl qualifiers stay readable, and json.Number values
// round trip as written (§7).
func (d *Document) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d.raw); err != nil {
		return nil, fmt.Errorf("serializing document: %w", err)
	}
	return buf.Bytes(), nil
}

// Component is a view of one component, joined across the raw and typed trees
// by its index.
type Component struct {
	Index int

	doc *Document
	raw map[string]any

	// typed is the input snapshot for this component. Nothing reads a mutable
	// field through it; see the Document doc comment.
	typed *cdx.Component
}

// Typed returns the cyclonedx-go view of this component as it was decoded from
// the input, or nil when the typed decode was unavailable.
//
// It is the seam §8 asks for and what later commands will read for the fields
// rio never rewrites. Do not read purl through it: writes land on the raw tree.
func (c *Component) Typed() *cdx.Component { return c.typed }

// Name returns component.name.
func (c *Component) Name() string { return stringField(c.raw, "name") }

// Version returns component.version. rio never writes it, even where it
// disagrees with a repaired purl: that divergence is intentional (§6.4).
func (c *Component) Version() string { return stringField(c.raw, "version") }

// Group returns component.group.
func (c *Component) Group() string { return stringField(c.raw, "group") }

// PURL returns component.purl.
func (c *Component) PURL() string { return stringField(c.raw, "purl") }

// BOMRef returns component.bom-ref. rio never writes it (§6.4).
func (c *Component) BOMRef() string { return stringField(c.raw, "bom-ref") }

// SetPURL rewrites component.purl in the raw tree. It is the only component
// field any transform is allowed to write (§6.4).
func (c *Component) SetPURL(purl string) {
	if c.raw == nil {
		return
	}
	c.raw["purl"] = purl
}

// Properties returns the component's own properties, as written by its
// generator.
func (c *Component) Properties() []Property {
	list, _ := c.raw["properties"].([]any)
	out := make([]Property, 0, len(list))
	for _, entry := range list {
		obj, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, Property{Name: stringField(obj, "name"), Value: stringField(obj, "value")})
	}
	return out
}

// AddProperty queues a property for this component. Queued properties are
// sorted by name then value and appended by Document.Finalize (§7).
func (c *Component) AddProperty(name, value string) {
	if c.raw == nil {
		return
	}
	c.doc.pendingComp[c.Index] = append(c.doc.pendingComp[c.Index], Property{Name: name, Value: value})
}

// AppendIdentityEvidence adds an evidence.identity entry in the 1.6 array
// form, appending when the component already carries one (§4.3b).
func (c *Component) AppendIdentityEvidence(field string, confidence float64, value string) {
	if c.raw == nil {
		return
	}
	evidence, ok := c.raw["evidence"].(map[string]any)
	if !ok {
		evidence = map[string]any{}
		c.raw["evidence"] = evidence
	}

	entry := map[string]any{
		"field":      field,
		"confidence": json.Number(formatConfidence(confidence)),
		"methods": []any{map[string]any{
			"technique":  "other",
			"confidence": json.Number(formatConfidence(confidence)),
			"value":      value,
		}},
	}

	switch identity := evidence["identity"].(type) {
	case []any:
		evidence["identity"] = append(identity, entry)
	case map[string]any:
		// A 1.5 object survived here; uplift wraps it, so this is belt and
		// braces for a document that skipped uplift.
		evidence["identity"] = []any{identity, entry}
	default:
		evidence["identity"] = []any{entry}
	}
}

func formatConfidence(c float64) string {
	s := strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", c), "0"), ".")
	if s == "" || s == "-" {
		return "0"
	}
	return s
}

func stringField(obj map[string]any, key string) string {
	if obj == nil {
		return ""
	}
	s, _ := obj[key].(string)
	return s
}

// ComponentRef locates one component anywhere in the document, including
// nested ones, for read-only checks.
//
// §5 step 4 gates "every component", and a component nested under another is
// still shipped. The transform layer stays on the top-level array, because
// that is what the join by index in §8 addresses, so this is deliberately a
// separate read-only walk rather than a widening of Components().
type ComponentRef struct {
	// Path locates the component for a human, e.g. "components[3]" or
	// "components[3].components[1]".
	Path    string
	Group   string
	Name    string
	Version string
	PURL    string
}

// EveryComponent walks the whole component tree in document order.
func (d *Document) EveryComponent() []ComponentRef {
	var out []ComponentRef
	walkComponents(d.raw["components"], "components", &out)
	return out
}

func walkComponents(node any, path string, out *[]ComponentRef) {
	list, ok := node.([]any)
	if !ok {
		return
	}
	for i, entry := range list {
		here := fmt.Sprintf("%s[%d]", path, i)
		obj, ok := entry.(map[string]any)
		if !ok {
			// A non-object entry is schema-invalid; validation reports it.
			// Record it so a check can still name where it sits.
			*out = append(*out, ComponentRef{Path: here})
			continue
		}
		*out = append(*out, ComponentRef{
			Path:    here,
			Group:   stringField(obj, "group"),
			Name:    stringField(obj, "name"),
			Version: stringField(obj, "version"),
			PURL:    stringField(obj, "purl"),
		})
		walkComponents(obj["components"], here+".components", out)
	}
}
