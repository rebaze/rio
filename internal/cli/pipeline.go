package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/rebaze/rio/internal/buildcontext"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/manifest"
	"github.com/rebaze/rio/internal/receipt"
	"github.com/spf13/cobra"
)

type pipelineOptions struct {
	receipt, gate      string
	artifacts, targets []string
	skip, json         bool
}
type invocation struct {
	store *receipt.Store
	doc   receipt.Document
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
	mode := man.Gate.Mode
	if cmd.Flags().Changed("gate") {
		mode = o.gate
	}
	if mode != gateFail && mode != gateWarn {
		return usageErrorf("no receipt created: --gate must be fail or warn")
	}
	selected := map[string]bool{}
	for _, id := range o.artifacts {
		if selected[id] {
			return usageErrorf("duplicate --artifact %q", id)
		}
		selected[id] = true
	}
	// Manifest validation is configuration work; input resolution belongs to the
	// invocation so ordinary missing/broken inputs can leave a failed receipt.
	s, e := receipt.Start(g.out, o.receipt, "pipeline", Version())
	if e != nil {
		return usageErrorf("no receipt created: %v", e)
	}
	r := &invocation{store: s, doc: s.Initial}
	r.doc.Run.Overrides = map[string]string{}
	for _, flag := range []string{"gate", "skip-delivery"} {
		if cmd.Flags().Changed(flag) {
			r.doc.Run.Overrides[flag] = cmd.Flags().Lookup(flag).Value.String()
		}
	}
	defer func() {
		if err != nil {
			r.doc.Exceptions = append(r.doc.Exceptions, safeCode(err))
			r.doc.Run.Outcome = "failed"
			if r.doc.Run.Stages["delivery"] == "partial" {
				r.doc.Run.Outcome = "partial"
			}
		} else {
			r.doc.Run.Outcome = "success"
		}
		r.doc.Run.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		pub, persist := s.Publish(r.doc)
		if closeErr := s.Close(); persist == nil {
			persist = closeErr
		}
		if persist != nil {
			err = internalErrorf("receipt persistence failed; a request may have happened; output may exist at %s; recover locally from %s without resubmitting: %v", s.Path, s.Dir, persist)
		}
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
	resolved, e := resolveArtifacts(man)
	if e != nil {
		r.doc.Run.Stages["intake"] = "failed"
		r.doc.Exceptions = append(r.doc.Exceptions, "input_resolution_failed")
		return e
	}
	var inputs []resolvedArtifact
	for _, input := range resolved {
		if len(o.artifacts) > 0 && !selected[input.Spec.ID] {
			r.doc.Exclusions = append(r.doc.Exclusions, receipt.Exclusion{ArtifactID: input.Spec.ID, Reason: "artifact-filter"})
			continue
		}
		inputs = append(inputs, input)
		delete(selected, input.Spec.ID)
	}
	if len(selected) > 0 {
		r.doc.Run.Stages["intake"] = "failed"
		return usageErrorf("unknown artifact selection")
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
			r.doc.Artifacts[i].State = "failed"
			r.doc.Artifacts[i].ErrorCode = "normalization_failed"
			r.doc.Run.Stages["normalize"] = "failed"
			return e
		}
		artifacts = append(artifacts, a)
		r.doc.Artifacts[i] = compactArtifact(a)
	}
	r.doc.Run.Stages["intake"] = "completed"
	r.doc.Run.Stages["normalize"] = "completed"
	r.doc.Run.Stages["checks"] = "passed"
	if e = writeAll(man, artifacts, s.Dir, false); e != nil {
		r.doc.Run.Stages["normalize"] = "failed"
		return e
	}
	config, e := delivery.ParseConfig(man.Delivery, man.Dir, man.SHA256)
	if e != nil {
		return e
	}
	if len(config.Targets) > 0 {
		// Describe failed-gate destinations offline before enforcing the gate. The
		// actual request policy is resolved separately, only after this check.
		plan, e := delivery.PlanBatch(config, filepath.Join(s.Dir, "index.json"), delivery.PlanOptions{Targets: o.targets, AllowFailedGate: true}, providers(config.Directory))
		if e != nil {
			return e
		}
		if e = r.describeDeliveries(plan); e != nil {
			return e
		}
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
	opts := deliveryOptions{index: filepath.Join(s.Dir, "index.json"), targets: o.targets, allowFailed: mode == gateWarn, receipt: r}
	result, e := executeDeliverBatch(cmd, g, opts, nil)
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
				changes.Metadata = append(changes.Metadata, metadataChange(c.Field, c.Before, c.After, "context-file"))
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
	var safe *delivery.Error
	if errors.As(e, &safe) {
		return safe.Code
	}
	return "execution_failed"
}
