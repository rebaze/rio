package index

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/rebaze/rio/internal/gate"
)

// NormalizationScope describes the selected universe, not all possible modules.
type NormalizationScope struct {
	Version           int                `json:"version"`
	ManifestSHA256    string             `json:"manifestSHA256"`
	SpecVersionFloor  string             `json:"specVersionFloor"`
	ExplicitArtifacts []string           `json:"explicitArtifacts"`
	ArtifactSets      []ArtifactSetScope `json:"artifactSets"`
	Artifacts         []ArtifactScope    `json:"artifacts"`
	opaque            json.RawMessage
}
type ArtifactSetScope struct {
	Source      string   `json:"source"`
	Modules     string   `json:"modules"`
	Exclude     []string `json:"exclude"`
	IDFrom      string   `json:"idFrom"`
	SBOM        string   `json:"sbom"`
	ArtifactIDs []string `json:"artifactIDs"`
}
type ArtifactScope struct {
	ID           string           `json:"id"`
	DeclaredSBOM string           `json:"declaredSBOM"`
	Input        string           `json:"input"`
	Selection    *Selection       `json:"selection,omitempty"`
	Transforms   []TransformScope `json:"transforms"`
}
type TransformScope struct {
	Name    string            `json:"name"`
	Options map[string]string `json:"options"`
}

type EffectiveChecks struct {
	Version               int               `json:"version"`
	Mode                  string            `json:"mode"`
	ComponentScope        string            `json:"componentScope"`
	ComponentCount        int               `json:"componentCount"`
	ComponentRequirements []string          `json:"componentRequirements"`
	ComponentEvaluation   string            `json:"componentEvaluation"`
	Evaluations           []gate.Evaluation `json:"evaluations"`
	SchemaValidation      string            `json:"schemaValidation"`
	GraphCheck            string            `json:"graphCheck"`
	GraphFindings         int               `json:"graphFindings"`
	opaque                json.RawMessage
}

// decodeExtension strictly checks known versions; future versions remain opaque.
func decodeExtension(b []byte, target any) (int, json.RawMessage, error) {
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(b, &header); err != nil {
		return 0, nil, err
	}
	if header.Version < 1 {
		return 0, nil, fmt.Errorf("invalid extension version")
	}
	if header.Version != 1 {
		return header.Version, append(json.RawMessage(nil), b...), nil
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	d.UseNumber()
	return header.Version, nil, d.Decode(target)
}
func (s *NormalizationScope) UnmarshalJSON(b []byte) error {
	type wire NormalizationScope
	var w wire
	v, raw, err := decodeExtension(b, &w)
	if err != nil {
		return err
	}
	*s = NormalizationScope(w)
	s.Version = v
	s.opaque = raw
	return nil
}
func (s NormalizationScope) MarshalJSON() ([]byte, error) {
	if len(s.opaque) > 0 {
		return s.opaque, nil
	}
	type wire NormalizationScope
	return json.Marshal(wire(s))
}
func (c *EffectiveChecks) UnmarshalJSON(b []byte) error {
	type wire EffectiveChecks
	var w wire
	v, raw, err := decodeExtension(b, &w)
	if err != nil {
		return err
	}
	*c = EffectiveChecks(w)
	c.Version = v
	c.opaque = raw
	return nil
}
func (c EffectiveChecks) MarshalJSON() ([]byte, error) {
	if len(c.opaque) > 0 {
		return c.opaque, nil
	}
	type wire EffectiveChecks
	return json.Marshal(wire(c))
}

func (s *NormalizationScope) Validate(idx *Index) error {
	if s == nil {
		return nil
	}
	bad := func() error { return fmt.Errorf("invalid normalization scope") }
	if s.Version < 1 {
		return bad()
	}
	if s.Version != 1 {
		return nil
	}
	if s.ManifestSHA256 != idx.Manifest.SHA256 || !digestPattern.MatchString(s.ManifestSHA256) || (s.SpecVersionFloor != "1.5" && s.SpecVersionFloor != "1.6") || s.Artifacts == nil || s.ExplicitArtifacts == nil || s.ArtifactSets == nil || len(s.Artifacts) != len(idx.Artifacts) {
		return bad()
	}
	sets := map[string][]string{}
	explicit := []string{}
	for i, a := range s.Artifacts {
		actual := idx.Artifacts[i]
		if a.ID != actual.ID || a.Input != actual.Input.Path || a.DeclaredSBOM == "" || !reflect.DeepEqual(a.Selection, actual.Selection) || a.Transforms == nil || len(a.Transforms) != len(actual.Transforms) {
			return bad()
		}
		if a.Selection == nil {
			explicit = append(explicit, a.ID)
		} else {
			sets[a.Selection.Source] = append(sets[a.Selection.Source], a.ID)
		}
		for _, tr := range a.Transforms {
			if tr.Name == "" || tr.Options == nil {
				return bad()
			}
		}
	}
	if !reflect.DeepEqual(explicit, s.ExplicitArtifacts) {
		return bad()
	}
	for i, set := range s.ArtifactSets {
		if set.Source != fmt.Sprintf("artifactSets[%d]", i) || set.Modules == "" || set.IDFrom != "module-directory" || set.SBOM == "" || set.Exclude == nil || set.ArtifactIDs == nil {
			return bad()
		}
		ids := sets[set.Source]
		if ids == nil {
			ids = []string{}
		}
		if !reflect.DeepEqual(ids, set.ArtifactIDs) {
			return bad()
		}
		delete(sets, set.Source)
	}
	if len(sets) > 0 {
		return bad()
	}
	return nil
}

func (c *EffectiveChecks) Validate(a Artifact) error {
	if c == nil {
		return nil
	}
	bad := func() error { return fmt.Errorf("invalid effective checks") }
	if c.Version < 1 {
		return bad()
	}
	if c.Version != 1 {
		return nil
	}
	if (c.Mode != "warn" && c.Mode != "fail") || c.ComponentScope != "all components including nested" || c.ComponentCount < a.Components || c.ComponentRequirements == nil || c.Evaluations == nil || c.GraphCheck != "dangling-dependency-references" || c.GraphFindings != len(a.IntegrityFindings) {
		return bad()
	}
	schema := "not-available"
	if a.SchemaValidated {
		schema = "pass"
	}
	if c.SchemaValidation != schema {
		return bad()
	}
	selection := map[string]bool{}
	for _, r := range c.ComponentRequirements {
		if (r != "name" && r != "version" && r != "purl") || selection[r] {
			return bad()
		}
		selection[r] = true
	}
	state := "evaluated"
	if len(selection) == 0 || c.ComponentCount == 0 {
		state = "not-evaluated"
	}
	if c.ComponentEvaluation != state {
		return bad()
	}
	if len(c.Evaluations) != 2+len(selection) {
		return bad()
	}
	seen := map[string]bool{}
	for _, e := range c.Evaluations {
		key := e.Scope + "/" + e.Requirement
		if seen[key] {
			return bad()
		}
		seen[key] = true
		count := 1
		switch e.Scope {
		case "subject":
			if e.Requirement != "name" && e.Requirement != "version" {
				return bad()
			}
		case "components":
			if !selection[e.Requirement] {
				return bad()
			}
			count = c.ComponentCount
		default:
			return bad()
		}
		failed := 0
		for _, f := range a.GateFindings {
			if f.Subject != (e.Scope == "subject") {
				continue
			}
			for _, m := range f.Missing {
				if m == e.Requirement {
					failed++
				}
			}
		}
		outcome := "pass"
		if count == 0 {
			outcome = "not-evaluated"
		} else if failed > 0 {
			outcome = "fail"
		}
		if e.Evaluated != count || e.Failed != failed || failed > count || e.Outcome != outcome {
			return bad()
		}
	}
	expected := GateOK
	if len(a.GateFindings) > 0 {
		expected = GateFail
	}
	if a.Gate != expected {
		return bad()
	}
	return nil
}
