package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/rebaze/rio/internal/buildcontext"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/manifest"
	"github.com/rebaze/rio/internal/receipt"
	"github.com/spf13/cobra"
)

type pipelineOptions struct {
	operation          string
	attest             bool
	receipt, gate      string
	artifacts, targets []string
	skip, json         bool
}
type invocation struct {
	publication *receipt.Publication
	store       *receipt.Store
	doc         receipt.Document
}

func configurePipeline(cmd *cobra.Command, g *globalOptions, stdout, stderr io.Writer) {
	var o pipelineOptions
	cmd.Short = "Run the configured SBOM pipeline and write one compact receipt"
	cmd.Long = "rio consumes the SBOMs in rio.yaml, adds configured metadata, checks quality,\nand delivers to configured destinations. One invocation writes one run receipt.\n\nRoot execution, deliver and reconciliation may use the network. Normalize, plan,\nrecord inspect and record report remain offline. HTTP acceptance is not ingestion."
	cmd.Args = cobra.NoArgs
	f := cmd.Flags()
	f.StringVar(&o.receipt, "receipt", "", "new public receipt path (default <out>/runs/<run-id>/record.json)")
	f.StringVar(&o.gate, "gate", "", "gate policy: fail or warn (flag > manifest > fail)")
	f.StringArrayVar(&o.artifacts, "artifact", nil, "artifact ID filter (repeatable; default all)")
	f.StringArrayVar(&o.targets, "target", nil, "delivery target filter (repeatable; default all)")
	f.BoolVar(&o.skip, "skip-delivery", false, "complete local stages without delivery")
	f.BoolVar(&o.json, "json", false, "print structured run result and receipt location")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error { return runPipeline(cmd, g, o, stdout, stderr) }
}
func runPipeline(cmd *cobra.Command, g *globalOptions, o pipelineOptions, stdout, stderr io.Writer) (err error) {
	man, e := manifest.Load(g.manifest)
	if e != nil {
		return usageErrorf("no receipt created: %v", e)
	}
	mode, e := effectiveGate(cmd, man, o)
	if e != nil {
		return e
	}
	effective := *g
	effective.out = effectiveOutput(cmd, g, man)
	g = &effective
	// Manifest validation is configuration work; input resolution belongs to the
	// invocation so ordinary missing/broken inputs can leave a failed receipt.
	s, e := receipt.Start(g.out, o.receipt, pipelineOperation(o), Version())
	if e != nil {
		return usageErrorf("no receipt created: %v", e)
	}
	r := &invocation{store: s, doc: s.Initial}
	r.captureOverrides(cmd)
	defer func() {
		pub, finishErr := r.finish(err)
		err = finishErr
		result := struct {
			RunID        string              `json:"runId"`
			Outcome      string              `json:"outcome"`
			RunDirectory string              `json:"runDirectory"`
			Receipt      receipt.Publication `json:"receipt"`
		}{s.ID, r.doc.Run.Outcome, s.Dir, pub}
		if o.json {
			if e := json.NewEncoder(stdout).Encode(result); e != nil {
				err = internalErrorf("writing run result: %v", e)
			}
		} else {
			fmt.Fprintf(stdout, "run %s: %s\nreceipt: %s\n", s.ID, r.doc.Run.Outcome, s.Path)
		}
	}()
	r.doc.Run.Stages["intake"] = "incomplete"
	if o.operation == "normalize" {
		r.doc.Run.Stages["delivery"] = "not-applicable"
	}
	// Capture known declarations before resolving inputs. A missing SBOM must
	// not erase configured destination coverage from the failure receipt.
	var config delivery.Config
	wanted := map[string]bool{}
	for _, id := range o.artifacts {
		wanted[id] = true
	}
	var declared []resolvedArtifact
	for _, a := range man.Artifacts {
		if len(wanted) == 0 || wanted[a.ID] {
			declared = append(declared, resolvedArtifact{Spec: a})
			r.doc.Artifacts = append(r.doc.Artifacts, receipt.Artifact{ID: a.ID, State: "not-attempted"})
		}
	}
	if o.operation != "normalize" {
		config, e = delivery.ParseConfig(man.Delivery, man.Dir, man.SHA256)
		if e != nil {
			return e
		}
		routing, excluded, e := describeRouting(config, declared, o)
		if e != nil {
			return e
		}
		r.applyRouting(routing, excluded)
	}
	if e = s.Checkpoint(r.doc); e != nil {
		return internalErrorf("checkpoint: %v", e)
	}
	resolved, e := resolveArtifacts(man, o.artifacts)
	if e != nil {
		r.doc.Run.Stages["intake"] = "failed"
		r.doc.Exceptions = append(r.doc.Exceptions, "input_resolution_failed")
		if len(man.ArtifactSets) > 0 {
			r.doc.Exceptions = append(r.doc.Exceptions, "artifact-set-membership-unresolved")
		}
		return e
	}
	inputs, excluded, e := selectInputs(resolved, o.artifacts)
	if e != nil {
		r.doc.Run.Stages["intake"] = "failed"
		return e
	}
	r.doc.Artifacts = nil
	r.doc.Deliveries = nil
	r.doc.Exclusions = append(excluded, declaredExclusions(man)...)
	if o.operation != "normalize" {
		routing, exclusions, e := describeRouting(config, inputs, o)
		if e != nil {
			return e
		}
		r.applyRouting(routing, exclusions)
	}
	for _, input := range inputs {
		r.doc.Artifacts = append(r.doc.Artifacts, receipt.Artifact{ID: input.Spec.ID, State: "not-attempted"})
	}
	if e = s.Checkpoint(r.doc); e != nil {
		return internalErrorf("checkpoint: %v", e)
	}
	artifacts := make([]*artifact, 0, len(inputs))
	contexts := map[string]*buildcontext.File{}
	for i, input := range inputs {
		a, e := normalizeArtifact(man, input, mode, contexts)
		if e != nil {
			if a != nil && a.inputSHA != "" {
				r.doc.Artifacts[i].Input = &receipt.Bytes{Path: a.inputRel, SHA256: a.inputSHA, Size: a.inputSize}
			}
			r.doc.Artifacts[i].State = "failed"
			r.doc.Artifacts[i].ErrorCode = "normalization_failed"
			if a == nil || !a.prepared {
				r.doc.Artifacts[i].ErrorCode = "input_failed"
				r.doc.Run.Stages["intake"] = "failed"
				if i > 0 {
					r.doc.Run.Stages["normalize"] = "incomplete"
				}
			} else {
				r.doc.Run.Stages["normalize"] = "failed"
				if i == len(inputs)-1 {
					r.doc.Run.Stages["intake"] = "completed"
				}
			}
			return e
		}
		r.doc.Run.Stages["normalize"] = "incomplete"
		r.doc.Run.Stages["checks"] = "incomplete"
		artifacts = append(artifacts, a)
		r.doc.Artifacts[i] = compactArtifact(a)
	}
	r.doc.Run.Stages["intake"] = "completed"
	r.doc.Run.Stages["normalize"] = "completed"
	r.doc.Run.Stages["checks"] = "passed"
	if e = writeAll(man, artifacts, s.Dir, o.attest); e != nil {
		r.doc.Run.Stages["normalize"] = "failed"
		return e
	}
	if o.operation == "normalize" {
		r.doc.Run.Stages["delivery"] = "not-applicable"
		for _, a := range artifacts {
			if !a.gate.OK() {
				r.doc.Run.Stages["checks"] = "failed"
			}
		}
		progress := stdout
		if o.json {
			progress = io.Discard
		}
		return report(artifacts, mode, g.quiet, progress, stderr)
	}
	gateFailed := false
	for _, a := range artifacts {
		if !a.gate.OK() {
			gateFailed = true
		}
	}
	if gateFailed {
		r.doc.Run.Stages["checks"] = "failed"
		if mode == gateFail {
			return gateFailure
		}
		r.doc.Exceptions = append(r.doc.Exceptions, "failed-gate-override")
	}
	if e = s.Checkpoint(r.doc); e != nil {
		return internalErrorf("checkpoint: %v", e)
	}
	if o.skip {
		r.doc.Run.Stages["delivery"] = "skipped"
		return nil
	}
	if len(config.Targets) == 0 {
		r.doc.Run.Stages["delivery"] = "not-configured"
		return nil
	}
	plan, e := delivery.PlanBatch(config, filepath.Join(s.Dir, "index.json"), delivery.PlanOptions{Targets: o.targets, AllowFailedGate: mode == gateWarn}, providers(config.Directory))
	if e != nil {
		return e
	}
	opts := deliveryOptions{index: filepath.Join(s.Dir, "index.json"), targets: o.targets, allowFailed: mode == gateWarn, receipt: r, planned: &plannedBatch{config: config, plan: plan}}
	result, e := executeDeliverBatch(cmd, g, opts)
	r.doc.Run.Stages["delivery"] = "completed"
	if e != nil {
		r.doc.Run.Stages["delivery"] = "failed"
		if result.Outcome == "partial" {
			r.doc.Run.Stages["delivery"] = "partial"
		}
		code := result.ExitCode
		if code == 0 {
			code = 2
		}
		return &exitError{code: code, err: e}
	}
	return nil
}
func compactArtifact(a *artifact) receipt.Artifact {
	out := receipt.Artifact{ID: a.spec.ID, State: "completed", Input: &receipt.Bytes{Path: a.inputRel, SHA256: a.inputSHA, Size: a.inputSize}, Output: &receipt.Bytes{Path: a.spec.ID + ".cdx.json", SHA256: delivery.Digest(a.output), Size: int64(len(a.output))}}
	gateState := "pass"
	if !a.gate.OK() {
		gateState = "fail"
	}
	if a.checks != nil {
		c := a.checks
		out.Checks = &receipt.Checks{Mode: c.Mode, Gate: gateState, Schema: c.SchemaValidation, SubjectRequirements: []string{"name", "version"}, ComponentRequirements: c.ComponentRequirements, ComponentScope: c.ComponentScope, ComponentEvaluation: c.ComponentEvaluation, ComponentsEvaluated: c.ComponentCount, Findings: len(a.gate.Findings), GraphFindings: c.GraphFindings}
	}
	changes := &receipt.Changes{}
	if a.inputSpec != a.outputSpec {
		changes.SpecVersion = &receipt.SpecChange{From: a.inputSpec, To: a.outputSpec}
	}
	if a.context != nil {
		for _, c := range a.context.Changes {
			// A newly added native projection repeats the logical assertion. Keep
			// native replacements/removals when they carry distinct prior facts.
			if strings.HasPrefix(c.Target, "context:") {
				source := "context-file"
				for _, field := range a.context.Defaulted {
					if field == c.Field {
						source = "context-default"
						break
					}
				}
				changes.Metadata = append(changes.Metadata, metadataChange(c.Field, c.Before, c.After, source))
			} else if c.Before != nil {
				changes.Metadata = append(changes.Metadata, metadataChange(c.Target, c.Before, c.After, "context-file"))
			}
		}
	}
	if a.normalization != nil {
		for _, c := range a.normalization.Changes {
			if c.Rule != "context" && c.Rule != "spec-uplift" && !strings.HasPrefix(c.Rule, "repair-") {
				changes.Metadata = append(changes.Metadata, metadataChange(c.Target, c.Before, c.After, "manifest"))
			}
		}
		for _, stat := range a.stats {
			b := receipt.BulkChange{Operation: stat.ID, Scope: "top-level components", Evaluated: a.components, Applied: stat.Applied, Unmapped: stat.Unmapped, Skipped: stat.Skipped, Reasons: map[string]int{}}
			for _, n := range a.normalization.Unmapped {
				if n.Rule == stat.ID {
					b.Reasons[n.Reason]++
				}
			}
			changes.Bulk = append(changes.Bulk, b)
		}
	}
	if len(changes.Metadata) > 0 || changes.SpecVersion != nil || len(changes.Bulk) > 0 {
		out.Changes = changes
	}
	return out
}
func metadataChange(field string, before, after any, source string) receipt.Change {
	op := "replace"
	if before == nil {
		op = "add"
	}
	if after == nil {
		op = "remove"
	}
	return receipt.Change{Field: field, Operation: op, Before: receipt.SummarizeValue(before), After: receipt.SummarizeValue(after), Assertion: "producer", Source: source}
}
func safeCode(e error) string {
	if errors.Is(e, gateFailure) {
		return "gate-failed"
	}
	var safe *delivery.Error
	if errors.As(e, &safe) {
		return safe.Code
	}
	return "execution_failed"
}

func pipelineOperation(o pipelineOptions) string {
	if o.operation != "" {
		return o.operation
	}
	return "pipeline"
}
