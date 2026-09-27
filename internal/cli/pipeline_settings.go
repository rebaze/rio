package cli

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/dtrack"
	"github.com/rebaze/rio/internal/manifest"
	"github.com/rebaze/rio/internal/receipt"
	"github.com/spf13/cobra"
)

type plannedBatch struct {
	config delivery.Config
	plan   delivery.BatchPlan
}
type planRouting struct {
	Mode    string                    `json:"mode"`
	Targets map[string]receipt.Target `json:"targets,omitempty"`
	Pairs   []planPair                `json:"pairs,omitempty"`
}
type planPair struct {
	ArtifactID    string            `json:"artifactId"`
	Target        string            `json:"target"`
	Project       map[string]string `json:"project,omitempty"`
	ProjectSource string            `json:"projectSource,omitempty"`
	Transport     receipt.Transport `json:"transport"`
}

func effectiveOutput(cmd *cobra.Command, g *globalOptions, m *manifest.Manifest) string {
	if cmd.Flags().Changed("out") || m.Output.Directory == "" {
		return g.out
	}
	if filepath.IsAbs(m.Output.Directory) {
		return m.Output.Directory
	}
	return filepath.Join(m.Dir, m.Output.Directory)
}
func effectiveGate(cmd *cobra.Command, m *manifest.Manifest, o pipelineOptions) (string, error) {
	mode := m.Gate.Mode
	if o.operation == "normalize" && !m.Gate.ModeExplicit {
		mode = gateWarn
	}
	if cmd.Flags().Changed("gate") {
		mode = o.gate
	}
	if mode != gateWarn && mode != gateFail {
		return "", usageErrorf("no receipt created: --gate must be %q or %q, got %q", gateWarn, gateFail, mode)
	}
	return mode, nil
}
func selectInputs(inputs []resolvedArtifact, requested []string) ([]resolvedArtifact, []receipt.Exclusion, error) {
	seen := map[string]bool{}
	for _, id := range requested {
		if seen[id] {
			return nil, nil, usageErrorf("duplicate --artifact %q", id)
		}
		seen[id] = true
	}
	var selected []resolvedArtifact
	var excluded []receipt.Exclusion
	for _, input := range inputs {
		if len(requested) > 0 && !seen[input.Spec.ID] {
			excluded = append(excluded, receipt.Exclusion{ArtifactID: input.Spec.ID, Reason: "artifact-filter"})
			continue
		}
		selected = append(selected, input)
		delete(seen, input.Spec.ID)
	}
	if len(seen) > 0 {
		return nil, nil, usageErrorf("unknown artifact selection")
	}
	return selected, excluded, nil
}
func describeRouting(c delivery.Config, inputs []resolvedArtifact, o pipelineOptions) (planRouting, []receipt.Exclusion, error) {
	r := planRouting{Mode: "configured", Targets: map[string]receipt.Target{}}
	if len(c.Targets) == 0 {
		if len(o.targets) > 0 {
			return r, nil, usageErrorf("unknown target selection")
		}
		r.Mode = "not-configured"
		return r, nil, nil
	}
	ps := providers(c.Directory)
	if e := delivery.ValidateConfig(c, ps); e != nil {
		return r, nil, e
	}
	wanted := map[string]bool{}
	for _, id := range o.targets {
		if _, ok := c.Targets[id]; !ok || wanted[id] {
			return r, nil, usageErrorf("unknown or repeated target selection")
		}
		wanted[id] = true
	}
	labels := make([]string, 0, len(c.Targets))
	for id := range c.Targets {
		labels = append(labels, id)
	}
	sort.Strings(labels)
	var exclusions []receipt.Exclusion
	for _, label := range labels {
		declared := c.Targets[label]
		// The placeholder is only for validating the selector. It is never emitted as
		// resolved project identity and no SBOM/context bytes need to be read.
		symbolic := delivery.Subject{Name: "normalized-subject-name", Version: "normalized-subject-version"}
		d, _, e := delivery.DescribeTarget(c, label, "", symbolic, ps)
		if e != nil {
			return r, nil, e
		}
		target, _, _, e := compactDestination(d)
		if e != nil {
			return r, nil, e
		}
		r.Targets[label] = target
		for _, input := range inputs {
			if len(wanted) > 0 && !wanted[label] {
				exclusions = append(exclusions, receipt.Exclusion{ArtifactID: input.Spec.ID, Target: label, Reason: "target-filter"})
				continue
			}
			excluded := false
			for _, id := range declared.Exclude {
				if id == input.Spec.ID {
					excluded = true
					break
				}
			}
			if excluded {
				exclusions = append(exclusions, receipt.Exclusion{ArtifactID: input.Spec.ID, Target: label, Reason: "target-exclude"})
				continue
			}
			d, _, e = delivery.DescribeTarget(c, label, input.Spec.ID, symbolic, ps)
			if e != nil {
				return r, nil, e
			}
			_, project, transport, e := compactDestination(d)
			if e != nil {
				return r, nil, e
			}
			pair := planPair{ArtifactID: input.Spec.ID, Target: label, Project: project, Transport: transport}
			if d.Type == "dependency-track" {
				opts, _, e := dtrack.ValidateDescription(d)
				if e != nil {
					return r, nil, e
				}
				if opts.Project.FromSubject {
					pair.Project = nil
					pair.ProjectSource = "normalized-subject"
				}
			}
			r.Pairs = append(r.Pairs, pair)
		}
	}
	if o.skip {
		r.Mode = "skipped"
	}
	return r, exclusions, nil
}
func (r *invocation) applyRouting(routing planRouting, exclusions []receipt.Exclusion) {
	r.doc.Targets = routing.Targets
	r.doc.Exclusions = append(r.doc.Exclusions, exclusions...)
	for _, p := range routing.Pairs {
		r.doc.Deliveries = append(r.doc.Deliveries, receipt.Delivery{ArtifactID: p.ArtifactID, Target: p.Target, Project: p.Project, ProjectSource: p.ProjectSource, State: "unattempted", Transport: p.Transport})
	}
}
func declaredExclusions(m *manifest.Manifest) []receipt.Exclusion {
	var result []receipt.Exclusion
	for i, set := range m.ArtifactSets {
		for _, rule := range set.Exclude {
			result = append(result, receipt.Exclusion{Reason: "artifact-set-exclude", Rule: rule, Scope: fmt.Sprintf("artifactSets[%d]: %s", i, set.Modules)})
		}
	}
	return result
}

func (r *invocation) captureOverrides(cmd *cobra.Command) {
	if r.doc.Run.Overrides == nil {
		r.doc.Run.Overrides = map[string]string{}
	}
	for _, flag := range []string{"gate", "skip-delivery", "manifest", "out", "receipt", "artifact", "target", "attest", "allow-failed-gate"} {
		if f := cmd.Flags().Lookup(flag); f != nil && f.Changed {
			r.doc.Run.Overrides[flag] = f.Value.String()
		}
	}
}
