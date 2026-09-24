package delivery

import (
	"encoding/json"
	"github.com/rebaze/rio/internal/index"
	"gopkg.in/yaml.v3"
	"path/filepath"
	"sort"
)

const SnapshotBudget int64 = 256 << 20
const PairLimit = 1024

type PlanOptions struct {
	Artifacts, Targets []string
	AllowFailedGate    bool
}
type Job struct {
	ArtifactID, Target, Record string
	Verified                   Verified
	Description                Description
	Provider                   Provider
}
type UnusedRule struct {
	Target     string `json:"target"`
	ArtifactID string `json:"artifactId"`
	Rule       string `json:"rule"`
}
type BatchPlan struct {
	IndexSHA256, ManifestSHA256 string
	Jobs                        []Job
	UnusedRules                 []UnusedRule
}

// ValidateConfig validates every target and override with a placeholder subject.
// Only selected jobs resolve actual subjects, credentials or transport files.
func ValidateConfig(c Config, registry map[string]Provider) error {
	var empty yaml.Node
	empty.Encode(map[string]any{})
	for _, id := range sortedTargets(c.Targets) {
		t := c.Targets[id]
		p, ok := registry[t.Type]
		if !ok {
			return Fail("unsupported_adapter", "target.type")
		}
		if _, e := p.Describe(t.Options, empty, Subject{"validation", "validation"}); e != nil {
			return e
		}
		keys := make([]string, 0, len(t.Overrides))
		for id := range t.Overrides {
			keys = append(keys, id)
		}
		sort.Strings(keys)
		for _, id := range keys {
			if _, e := p.Describe(t.Options, t.Overrides[id], Subject{"validation", "validation"}); e != nil {
				return e
			}
		}
	}
	return nil
}
func DescribeTarget(c Config, target, artifact string, subject Subject, registry map[string]Provider) (Description, Provider, error) {
	t, ok := c.Targets[target]
	if !ok {
		return Description{}, nil, Fail("target_missing", "configured target required")
	}
	p := registry[t.Type]
	if p == nil {
		return Description{}, nil, Fail("unsupported_adapter", "target.type")
	}
	ov, ok := t.Overrides[artifact]
	if !ok {
		ov.Encode(map[string]any{})
	}
	d, e := p.Describe(t.Options, ov, subject)
	d.DestinationName = target
	return d, p, e
}
func sortedTargets(ts map[string]TargetConfig) []string {
	a := make([]string, 0, len(ts))
	for k := range ts {
		a = append(a, k)
	}
	sort.Strings(a)
	return a
}
func filter(values []string, known map[string]bool, field string) (map[string]bool, error) {
	selected := map[string]bool{}
	if len(values) == 0 {
		for k := range known {
			selected[k] = true
		}
		return selected, nil
	}
	for _, v := range values {
		if !known[v] || selected[v] {
			return nil, Fail("invalid_filter", field+" unknown or repeated")
		}
		selected[v] = true
	}
	return selected, nil
}
func excluded(t TargetConfig, id string) bool {
	for _, v := range t.Exclude {
		if v == id {
			return true
		}
	}
	return false
}

// PlanBatch captures index once and each selected payload once; jobs share private bytes.
func PlanBatch(c Config, indexPath string, o PlanOptions, registry map[string]Provider) (BatchPlan, error) {
	return planBatch(c, indexPath, o, registry, ReadBounded)
}
func planBatch(c Config, indexPath string, o PlanOptions, registry map[string]Provider, read func(string, int64) ([]byte, error)) (BatchPlan, error) {
	plan := BatchPlan{ManifestSHA256: c.SHA256, Jobs: []Job{}, UnusedRules: []UnusedRule{}}
	if len(c.Targets) == 0 {
		return plan, Fail("no_targets", "rio.yaml delivery.targets required")
	}
	if e := ValidateConfig(c, registry); e != nil {
		return plan, e
	}
	raw, e := read(indexPath, IndexLimit)
	if e != nil {
		return plan, e
	}
	plan.IndexSHA256 = Digest(raw)
	idx, e := ParseIndex(raw)
	if e != nil {
		return plan, e
	}
	return planResolved(plan, c, indexPath, idx, o, registry, read)
}
func planResolved(plan BatchPlan, c Config, indexPath string, idx index.Index, o PlanOptions, registry map[string]Provider, read func(string, int64) ([]byte, error)) (BatchPlan, error) {
	artifacts := map[string]bool{}
	targets := map[string]bool{}
	for _, a := range idx.Artifacts {
		artifacts[a.ID] = true
	}
	for k := range c.Targets {
		targets[k] = true
	}
	as, e := filter(o.Artifacts, artifacts, "artifact")
	if e != nil {
		return plan, e
	}
	ts, e := filter(o.Targets, targets, "target")
	if e != nil {
		return plan, e
	}
	order := sortedTargets(c.Targets)
	for _, id := range order {
		t := c.Targets[id]
		for _, a := range t.Exclude {
			if !artifacts[a] {
				plan.UnusedRules = append(plan.UnusedRules, UnusedRule{id, a, "exclude"})
			}
		}
		for a := range t.Overrides {
			if !artifacts[a] {
				plan.UnusedRules = append(plan.UnusedRules, UnusedRule{id, a, "override"})
			}
		}
	}
	sort.Slice(plan.UnusedRules, func(i, j int) bool {
		a, b := plan.UnusedRules[i], plan.UnusedRules[j]
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		if a.ArtifactID != b.ArtifactID {
			return a.ArtifactID < b.ArtifactID
		}
		return a.Rule < b.Rule
	})
	count := 0
	for _, a := range idx.Artifacts {
		if as[a.ID] {
			for _, id := range order {
				if ts[id] && !excluded(c.Targets[id], a.ID) {
					count++
				}
			}
		}
	}
	if count == 0 {
		return plan, Fail("no_deliveries_selected", "no eligible artifact-target pairs")
	}
	if count > PairLimit {
		return plan, Fail("pair_limit", "maximum 1024 selected pairs")
	}
	var total int64
	seen := map[string]bool{}
	type modes struct {
		artifacts map[string]bool
		modes     map[string]bool
	}
	domains := map[string]*modes{}
	for _, a := range idx.Artifacts {
		if !as[a.ID] {
			continue
		}
		eligible := []string{}
		for _, id := range order {
			if ts[id] && !excluded(c.Targets[id], a.ID) {
				eligible = append(eligible, id)
			}
		}
		if len(eligible) == 0 {
			continue
		}
		v, e := verifyArtifactRead(indexPath, plan.IndexSHA256, idx, a.ID, o.AllowFailedGate, func(path string, limit int64) ([]byte, error) {
			remaining := SnapshotBudget - total
			if remaining < limit {
				limit = remaining
			}
			b, e := read(path, limit)
			if e != nil {
				if safe, ok := e.(*Error); ok && safe.Code == "size_limit" && remaining < PayloadLimit {
					return nil, Fail("snapshot_limit", "maximum total selected snapshot bytes 256 MiB")
				}
				return nil, e
			}
			total += int64(len(b))
			return b, nil
		})
		if e != nil {
			return plan, e
		}
		for _, id := range eligible {
			d, p, e := DescribeTarget(c, id, a.ID, v.Subject(), registry)
			if e != nil {
				return plan, e
			}
			identity := d.Type + ":" + string(d.Identity)
			if seen[identity] {
				return plan, Fail("target_collision", "multiple routes resolve to the same receiver/project")
			}
			seen[identity] = true
			if cp, ok := p.(interface {
				CollisionDomain(Description) (string, string)
			}); ok {
				domain, mode := cp.CollisionDomain(d)
				domain = d.Type + ":" + domain
				m := domains[domain]
				if m == nil {
					m = &modes{map[string]bool{}, map[string]bool{}}
					domains[domain] = m
				}
				m.artifacts[a.ID] = true
				m.modes[mode] = true
				if len(m.artifacts) > 1 && len(m.modes) > 1 {
					return plan, Fail("ambiguous_target", "mixed UUID and name/version at one receiver")
				}
			}
			key := PairKey(v.Source(), d)
			path, e := filepath.Abs(filepath.Join(filepath.Dir(indexPath), "deliveries", key))
			if e != nil {
				return plan, Fail("invalid_record_path", "automatic journal")
			}
			plan.Jobs = append(plan.Jobs, Job{a.ID, id, path, v, d, p})
		}
	}
	return plan, nil
}
func PairKey(s Source, d Description) string {
	b, _ := json.Marshal(struct {
		IndexSHA256  string          `json:"indexSHA256"`
		ArtifactID   string          `json:"artifactId"`
		OutputSHA256 string          `json:"outputSHA256"`
		Type         string          `json:"type"`
		Identity     json.RawMessage `json:"identity"`
	}{s.IndexSHA256, s.ArtifactID, s.OutputSHA256, d.Type, d.Identity})
	return Digest(b)
}
