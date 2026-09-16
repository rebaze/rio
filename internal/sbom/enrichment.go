package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/package-url/packageurl-go"
	"github.com/rebaze/rio/internal/enrichment"
)

// EnrichmentRecord is an additive, independently versioned extension to the
// normalization record. It describes only this run's effective changes.
type EnrichmentRecord struct {
	Version int                `json:"version"`
	Changes []EnrichmentChange `json:"changes"`
}

type EnrichmentChange struct {
	Field     string           `json:"field"`
	Target    string           `json:"target"`
	Before    any              `json:"before"`
	After     any              `json:"after"`
	Source    EnrichmentSource `json:"source"`
	Assertion string           `json:"assertion"`
}

type EnrichmentSource struct {
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Selector string `json:"selector"`
}

var (
	enrichmentLicenseOnce sync.Once
	enrichmentLicenses    map[string]bool
	enrichmentLicenseErr  error
)

// ValidateEnrichmentConfig uses Rio's embedded SPDX vocabulary. The manifest
// loader also calls it so plan and normalize reject the same invalid ID.
func ValidateEnrichmentConfig(cfg *enrichment.Resolved) error {
	if cfg == nil {
		return nil
	}
	for _, f := range cfg.Fields {
		if f.Field != "dataLicense" {
			continue
		}
		var id string
		if err := json.Unmarshal(f.Value, &id); err != nil {
			return fmt.Errorf("%s: dataLicense must be an SPDX identifier", f.Source)
		}
		enrichmentLicenseOnce.Do(func() {
			var schema struct {
				Enum []string `json:"enum"`
			}
			data, err := schemaFS.ReadFile("schemas/spdx.schema.json")
			if err == nil {
				err = json.Unmarshal(data, &schema)
			}
			enrichmentLicenseErr = err
			enrichmentLicenses = map[string]bool{}
			for _, v := range schema.Enum {
				enrichmentLicenses[v] = true
			}
		})
		if enrichmentLicenseErr != nil {
			return fmt.Errorf("reading embedded SPDX identifiers: %w", enrichmentLicenseErr)
		}
		if !enrichmentLicenses[id] {
			return fmt.Errorf("%s: dataLicense %q is not an SPDX identifier in Rio's embedded list", f.Source, id)
		}
	}
	return nil
}

// Enrich applies manifest assertions atomically. It changes only modeled
// metadata leaves and never rewrites document-local reference identifiers.
func (d *Document) Enrich(cfg *enrichment.Resolved, manifestPath, manifestSHA string) (*EnrichmentRecord, error) {
	if cfg == nil {
		return nil, nil
	}
	if cfg.Version != 1 {
		return nil, fmt.Errorf("unsupported enrichment version %d", cfg.Version)
	}
	if err := ValidateEnrichmentConfig(cfg); err != nil {
		return nil, err
	}
	data, err := json.Marshal(d.raw)
	if err != nil {
		return nil, err
	}
	working := *d
	working.raw = nil // Decode into a fresh map; reusing d.raw would break rollback.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&working.raw); err != nil {
		return nil, err
	}
	result := &EnrichmentRecord{Version: 1, Changes: []EnrichmentChange{}}
	identity := false
	for _, f := range cfg.Fields {
		var value any
		if err := json.Unmarshal(f.Value, &value); err != nil {
			return nil, fmt.Errorf("%s: invalid enrichment value: %w", f.Source, err)
		}
		target, before, after, changed, err := working.enrichField(f, value)
		if err != nil {
			return nil, fmt.Errorf("%s (%s): %w", f.Source, f.Field, err)
		}
		switch f.Field {
		case "subject.name", "subject.group", "subject.version", "subject.purl":
			identity = true
		}
		record := func(target string, before, after any, changed bool) {
			if changed {
				result.Changes = append(result.Changes, EnrichmentChange{
					Field: f.Field, Target: target, Before: before, After: after,
					Source: EnrichmentSource{Kind: "manifest", Path: manifestPath, SHA256: manifestSHA, Selector: f.Source}, Assertion: "producer",
				})
			}
		}
		record(target, before, after, changed)
		// Older generators may describe the same subject organization on metadata.
		// Do not introduce a conflicting assertion at the modern location. An
		// explicit replacement updates the corresponding existing legacy leaf too.
		target, before, after, changed, err = working.enrichLegacyOrganization(f, value)
		if err != nil {
			return nil, fmt.Errorf("%s (%s): %w", f.Source, f.Field, err)
		}
		record(target, before, after, changed)
	}
	if identity {
		if err := working.checkEnrichedIdentity(); err != nil {
			return nil, err
		}
	}
	if err := working.ValidateSelf(); err != nil {
		var noSchema *ErrNoSchema
		if !errors.As(err, &noSchema) {
			return nil, fmt.Errorf("enrichment does not produce valid CycloneDX %s metadata: %w", d.specVersion, err)
		}
	}
	d.raw = working.raw
	d.indexComponents()
	for _, change := range result.Changes {
		encoded, err := json.Marshal(struct {
			Version int `json:"version"`
			EnrichmentChange
		}{Version: 1, EnrichmentChange: change})
		if err != nil {
			return nil, err
		}
		d.AddMetadataProperty(PropertyPrefix+"enrichment", string(encoded))
	}
	return result, nil
}

func (d *Document) enrichField(f enrichment.Field, value any) (target string, before, after any, changed bool, err error) {
	switch f.Field {
	case "subject.securityContact", "subject.website", "subject.documentation", "subject.support":
		kinds := map[string]string{"subject.securityContact": "security-contact", "subject.website": "website", "subject.documentation": "documentation", "subject.support": "support"}
		return d.enrichReference(f, value.(string), kinds[f.Field])
	case "dataLicense":
		parent := d.metadata(true)
		before = parent["licenses"]
		if sameDataLicense(before, value.(string)) {
			return "/metadata/licenses", before, before, false, nil
		}
		after = []any{map[string]any{"license": map[string]any{"id": value}}}
		return assignEnriched(f, parent, "licenses", "/metadata/licenses", after)
	}
	parts := strings.Split(f.Field, ".")
	var parent map[string]any
	var path string
	switch parts[0] {
	case "subject":
		parent = d.metadataComponent(true)
		path = "/metadata/component"
		if len(parts) >= 2 && parts[1] == "manufacturer" && compareSpecVersions(d.specVersion, "1.6") < 0 {
			return "", nil, nil, false, fmt.Errorf("subject manufacturer requires CycloneDX 1.6 or newer; set output.specVersionFloor to 1.6")
		}
	case "producer":
		if compareSpecVersions(d.specVersion, "1.6") < 0 {
			return "", nil, nil, false, fmt.Errorf("SBOM producer organization requires CycloneDX 1.6 or newer; set output.specVersionFloor to 1.6")
		}
		parent = objectChild(d.metadata(true), "manufacturer")
		path = "/metadata/manufacturer"
	default:
		return "", nil, nil, false, fmt.Errorf("unsupported enrichment field %q", f.Field)
	}
	for _, part := range parts[1 : len(parts)-1] {
		parent = objectChild(parent, part)
		path += "/" + part
	}
	key := parts[len(parts)-1]
	return assignEnriched(f, parent, key, path+"/"+key, value)
}

func objectChild(parent map[string]any, key string) map[string]any {
	child, ok := parent[key].(map[string]any)
	if !ok {
		child = map[string]any{}
		parent[key] = child
	}
	return child
}

func assignEnriched(f enrichment.Field, parent map[string]any, key, path string, value any) (string, any, any, bool, error) {
	before := parent[key]
	if equivalentEnrichment(before, value) {
		return path, before, before, false, nil
	}
	if !emptyEnrichment(before) && !f.Replace {
		return path, nil, nil, false, fmt.Errorf("conflicts with existing %s; explicitly list %s in enrichment.replace to replace it", path, f.Field)
	}
	parent[key] = value
	return path, before, value, true, nil
}

func emptyEnrichment(v any) bool {
	switch v := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(v) == ""
	case []any:
		return len(v) == 0
	}
	return false
}

// URL and contact lists have no order semantics. An equal assertion should
// preserve the input's ordering instead of producing a cosmetic replacement.
func equivalentEnrichment(a, b any) bool {
	as, aok := a.([]any)
	bs, bok := b.([]any)
	if !aok || !bok {
		return reflect.DeepEqual(a, b)
	}
	contains := func(xs []any, v any) bool {
		for _, x := range xs {
			if reflect.DeepEqual(x, v) {
				return true
			}
		}
		return false
	}
	for _, v := range as {
		if !contains(bs, v) {
			return false
		}
	}
	for _, v := range bs {
		if !contains(as, v) {
			return false
		}
	}
	return true
}

func sameDataLicense(existing any, id string) bool {
	licenses, ok := existing.([]any)
	if !ok || len(licenses) != 1 {
		return false
	}
	choice, _ := licenses[0].(map[string]any)
	license, _ := choice["license"].(map[string]any)
	return license["id"] == id
}

func (d *Document) enrichReference(f enrichment.Field, uri, kind string) (string, any, any, bool, error) {
	parent := d.metadataComponent(true)
	before := parent["externalReferences"]
	refs, _ := before.([]any)
	matchingURI, conflictingURI := false, false
	for _, r := range refs {
		ref, _ := r.(map[string]any)
		if ref["type"] != kind {
			continue
		}
		if ref["url"] == uri {
			matchingURI = true
		} else {
			conflictingURI = true
		}
	}
	if conflictingURI && !f.Replace {
		return "", nil, nil, false, fmt.Errorf("conflicts with existing %s external reference; explicitly list %s in enrichment.replace to replace it", kind, f.Field)
	}
	next := make([]any, 0, len(refs)+1)
	added := false
	for _, r := range refs {
		ref, _ := r.(map[string]any)
		if ref["type"] != kind {
			next = append(next, r)
			continue
		}
		if ref["url"] == uri {
			// Preserve additional source evidence (comments/hashes) on the chosen
			// URI. Only exact duplicate entries can be removed without losing it.
			duplicate := false
			for _, kept := range next {
				if reflect.DeepEqual(kept, r) {
					duplicate = true
					break
				}
			}
			if !duplicate {
				next = append(next, r)
			}
			added = true
		} else if !matchingURI && !added {
			next = append(next, map[string]any{"type": kind, "url": uri})
			added = true
		}
	}
	if !added {
		next = append(next, map[string]any{"type": kind, "url": uri})
	}
	if reflect.DeepEqual(refs, next) {
		return "/metadata/component/externalReferences", before, before, false, nil
	}
	parent["externalReferences"] = next
	return "/metadata/component/externalReferences", before, next, true, nil
}

func (d *Document) checkEnrichedIdentity() error {
	subject := d.metadataComponent(false)
	raw := stringField(subject, "purl")
	if raw == "" {
		return nil
	}
	purl, err := packageurl.FromString(raw)
	if err != nil {
		return fmt.Errorf("enriched subject.purl is invalid: %w", err)
	}
	for _, check := range []struct{ field, want string }{{"name", purl.Name}, {"group", purl.Namespace}, {"version", purl.Version}} {
		got := stringField(subject, check.field)
		if got != "" && (check.field != "version" || check.want != "") && got != check.want {
			return fmt.Errorf("enriched subject.%s %q contradicts subject.purl %q; supply coherent identity values and explicit replacements", check.field, got, raw)
		}
	}
	return nil
}

func (d *Document) enrichLegacyOrganization(f enrichment.Field, value any) (string, any, any, bool, error) {
	parts := strings.Split(f.Field, ".")
	if len(parts) != 3 || parts[0] != "subject" {
		return "", nil, nil, false, nil
	}
	legacy := ""
	switch parts[1] {
	case "supplier":
		legacy = "supplier"
	case "manufacturer":
		legacy = "manufacture"
	default:
		return "", nil, nil, false, nil
	}
	organization, ok := d.metadata(false)[legacy].(map[string]any)
	if !ok || emptyEnrichment(organization[parts[2]]) {
		return "", nil, nil, false, nil
	}
	return assignEnriched(f, organization, parts[2], "/metadata/"+legacy+"/"+parts[2], value)
}
