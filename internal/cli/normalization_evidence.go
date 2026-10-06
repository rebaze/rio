package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/rebaze/rio/internal/index"
	"github.com/rebaze/rio/internal/manifest"
	"github.com/rebaze/rio/internal/sbom"
	"github.com/rebaze/rio/internal/transform"
)

func newNormalization() *index.Normalization {
	return &index.Normalization{Version: 1, Changes: []index.Change{}, Bookkeeping: []index.Change{}, Unmapped: []index.Unmapped{}, Skipped: []index.Skipped{}}
}

// captureChanges snapshots only the in-memory document; it never rereads inputs.
// Property queues are materialized by the existing finalization phase. Its diff
// separates qualifier retention from Rio bookkeeping without changing sort order.
func (a *artifact) captureChanges(rule string, resolution *transform.Resolution, repairs map[string]*transform.Resolution) error {
	data, err := a.doc.Bytes()
	if err != nil {
		return err
	}
	var next map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err = dec.Decode(&next); err != nil {
		return err
	}
	if a.normalization == nil {
		a.normalization = newNormalization()
		a.evidenceSnapshot = next
		return nil
	}
	changes := diffValues("", a.evidenceSnapshot, next, true, true)
	for _, c := range changes {
		c.Rule = rule
		c.Resolution = resolution
		for target, source := range repairs {
			if c.Target == target {
				c.Resolution = source
			}
		}
		bookkeeping := rule == "rio-bookkeeping"
		if strings.HasPrefix(c.Target, "/metadata/properties/") && rule != "context" {
			bookkeeping = true
		}
		if (strings.Contains(c.Target, "/evidence/") || strings.HasSuffix(c.Target, "/evidence")) && strings.HasPrefix(rule, "repair-") {
			bookkeeping = true
		}
		if rule == "rio-bookkeeping" && strings.HasPrefix(c.Target, "/components/") && strings.Contains(c.Target, "/properties/") {
			// Only qualifier retention is a substantive repair property. Other queued
			// Rio fields belong to bookkeeping.
			if obj, ok := c.After.(map[string]any); ok && obj["name"] == sbom.PropertyPrefix+"p2-qualifier" {
				bookkeeping = false
				c.Rule = "repair-purl/p2/qualifier-preservation"
			}
		}
		if bookkeeping {
			a.normalization.Bookkeeping = append(a.normalization.Bookkeeping, c)
		} else {
			a.normalization.Changes = append(a.normalization.Changes, c)
		}
	}
	a.evidenceSnapshot = next
	return nil
}

func pointerToken(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
func diffValues(path string, before, after any, bok, aok bool) []index.Change {
	if bok == aok && reflect.DeepEqual(before, after) {
		return nil
	}
	bm, bmap := before.(map[string]any)
	am, amap := after.(map[string]any)
	if bmap && amap || path == "" {
		keys := map[string]bool{}
		for k := range bm {
			keys[k] = true
		}
		for k := range am {
			keys[k] = true
		}
		order := make([]string, 0, len(keys))
		for k := range keys {
			order = append(order, k)
		}
		sort.Strings(order)
		var result []index.Change
		for _, k := range order {
			b, bok := bm[k]
			a, aok := am[k]
			result = append(result, diffValues(path+"/"+pointerToken(k), b, a, bok, aok)...)
		}
		return result
	}
	ba, barray := before.([]any)
	aa, aarray := after.([]any)
	if (barray || !bok) && aarray || barray && !aok {
		var result []index.Change
		for i := 0; i < max(len(ba), len(aa)); i++ {
			var b, a any
			bok, aok := i < len(ba), i < len(aa)
			if bok {
				b = ba[i]
			}
			if aok {
				a = aa[i]
			}
			result = append(result, diffValues(path+"/"+strconv.Itoa(i), b, a, bok, aok)...)
		}
		return result
	}
	op := "replace"
	if !bok {
		op = "add"
	}
	if !aok {
		op = "remove"
	}
	return []index.Change{{Target: path, Operation: op, Before: before, After: after}}
}

func (a *artifact) captureOutcomes(rule string, result transform.Result) {
	for _, n := range result.Notes {
		if n.Kind == transform.NoteUnmapped {
			a.normalization.Unmapped = append(a.normalization.Unmapped, index.Unmapped{Target: fmt.Sprintf("/components/%d", n.ComponentIndex), Rule: rule, PURL: n.PURL, Reason: n.Reason})
		}
		if n.Kind == transform.NoteSkipped {
			found := false
			for i := range a.normalization.Skipped {
				s := &a.normalization.Skipped[i]
				if s.Rule == rule && s.Reason == n.Reason {
					s.Count++
					found = true
					break
				}
			}
			if !found {
				a.normalization.Skipped = append(a.normalization.Skipped, index.Skipped{Rule: rule, Scope: "top-level components", Reason: n.Reason, Count: 1})
			}
		}
	}
}

func normalizationScope(man *manifest.Manifest, artifacts []*artifact) (*index.NormalizationScope, error) {
	s := &index.NormalizationScope{Version: 1, ManifestSHA256: man.SHA256, SpecVersionFloor: man.Output.SpecVersionFloor, ExplicitArtifacts: []string{}, ArtifactSets: []index.ArtifactSetScope{}, Artifacts: []index.ArtifactScope{}}
	for i, set := range man.ArtifactSets {
		s.ArtifactSets = append(s.ArtifactSets, index.ArtifactSetScope{Source: fmt.Sprintf("artifactSets[%d]", i), Modules: set.Modules, Exclude: append([]string{}, set.Exclude...), IDFrom: set.IDFrom, SBOM: set.Template.SBOM, ArtifactIDs: []string{}})
	}
	for _, a := range artifacts {
		row := index.ArtifactScope{ID: a.spec.ID, DeclaredSBOM: a.spec.SBOM, Input: a.inputRel, Selection: a.selection, Transforms: []index.TransformScope{}}
		for _, t := range a.spec.Transforms {
			options, err := transform.Describe(t.Name, t.Config)
			if err != nil {
				return nil, err
			}
			tr := index.TransformScope{Name: t.Name, Options: map[string]string{}}
			for _, option := range options {
				tr.Options[option.Key] = option.Value
			}
			row.Transforms = append(row.Transforms, tr)
		}
		s.Artifacts = append(s.Artifacts, row)
		if a.selection == nil {
			s.ExplicitArtifacts = append(s.ExplicitArtifacts, a.spec.ID)
		} else {
			for i := range s.ArtifactSets {
				if s.ArtifactSets[i].Source == a.selection.Source {
					s.ArtifactSets[i].ArtifactIDs = append(s.ArtifactSets[i].ArtifactIDs, a.spec.ID)
				}
			}
		}
	}
	return s, nil
}

func effectiveChecks(man *manifest.Manifest, a *artifact, mode string) *index.EffectiveChecks {
	schema := "not-available"
	if a.schemaValidated {
		schema = "pass"
	}
	state := "evaluated"
	if len(man.Gate.Require) == 0 || a.gate.ComponentCount == 0 {
		state = "not-evaluated"
	}
	return &index.EffectiveChecks{Version: 1, Mode: mode, ComponentScope: "all components including nested", ComponentCount: a.gate.ComponentCount, ComponentRequirements: append([]string{}, man.Gate.Require...), ComponentEvaluation: state, Evaluations: a.gate.Evaluations, SchemaValidation: schema, GraphCheck: "dangling-dependency-references", GraphFindings: len(a.integrity)}
}
