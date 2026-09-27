package cli

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/receipt"
)

// finish snapshots this invocation once. Persistence failure never retries work.
func (r *invocation) finish(workErr error) (receipt.Publication, error) {
	if workErr != nil {
		r.doc.Exceptions = append(r.doc.Exceptions, safeCode(workErr))
		r.doc.Run.Outcome = "failed"
		if r.doc.Run.Stages["delivery"] == "partial" {
			r.doc.Run.Outcome = "partial"
		}
	} else {
		r.doc.Run.Outcome = "success"
	}
	r.doc.Run.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	pub, persist := r.store.Publish(r.doc)
	if persist != nil {
		r.doc.Run.Outcome = "failed"
		r.doc.Exceptions = append(r.doc.Exceptions, "receipt-persistence-failed")
		// Retain a local failure checkpoint when storage still permits it.
		// This does not replace an already-published public snapshot.
		_ = r.store.Checkpoint(r.doc)
	}
	if e := r.store.Close(); persist == nil {
		persist = e
	}
	if persist != nil {
		return pub, internalErrorf("receipt persistence failed; a request may have happened; output may exist at %s; recover locally from %s without resubmitting: %v", r.store.Path, r.store.Dir, persist)
	}
	return pub, workErr
}
func startDeliveryInvocation(g *globalOptions, o deliveryOptions, plan delivery.BatchPlan, path string) (*invocation, error) {
	s, e := receipt.Start(g.out, path, "deliver", Version())
	if e != nil {
		return nil, usageErrorf("no receipt created: %v", e)
	}
	r := &invocation{store: s, doc: s.Initial}
	if e = r.consumePlan(plan, o.index); e != nil {
		s.Close()
		return nil, e
	}
	if e = r.describeDeliveries(plan); e != nil {
		s.Close()
		return nil, e
	}
	if e = s.Checkpoint(r.doc); e != nil {
		s.Close()
		return nil, e
	}
	return r, nil
}

// consumePlan describes only already-normalized bytes actually captured by the
// verified handoff. Earlier normalization changes never enter this invocation.
func (r *invocation) consumePlan(plan delivery.BatchPlan, indexPath string) error {
	idx, e := delivery.ParseIndex(plan.IndexBytes())
	if e != nil {
		return e
	}
	seen := map[string]bool{}
	for _, j := range plan.Jobs {
		if seen[j.ArtifactID] {
			continue
		}
		seen[j.ArtifactID] = true
		payloads := j.Verified.Payloads()
		if len(payloads) == 0 {
			continue
		}
		ref := payloads[0].Ref()
		if ref.Transformation != "identity" {
			return fmt.Errorf("unsupported pre-existing input representation")
		}
		a := receipt.Artifact{ID: j.ArtifactID, State: "completed", PreExisting: true}
		for _, prior := range idx.Artifacts {
			if prior.ID == j.ArtifactID {
				source := receipt.Bytes{Path: filepath.Join(filepath.Dir(indexPath), filepath.FromSlash(prior.Output.Path)), SHA256: ref.SHA256, Size: ref.Size}
				a.Input = &source
				output := source
				a.Output = &output
				gate := "pass"
				if prior.Gate == "fail" {
					gate = "fail"
				}
				schema := "not-available"
				if prior.SchemaValidated {
					schema = "pass"
				}
				a.Checks = &receipt.Checks{Mode: "pre-existing", Gate: gate, Schema: schema, ComponentScope: "not-recorded", ComponentEvaluation: "not-available", Findings: len(prior.GateFindings)}
				if c := prior.Checks; c != nil {
					a.Checks.ComponentScope = c.ComponentScope
					a.Checks.ComponentRequirements = c.ComponentRequirements
					a.Checks.SubjectRequirements = []string{"name", "version"}
					a.Checks.ComponentsEvaluated = c.ComponentCount
					a.Checks.ComponentEvaluation = c.ComponentEvaluation
					a.Checks.GraphFindings = c.GraphFindings
				}
			}
		}
		r.doc.Artifacts = append(r.doc.Artifacts, a)
	}
	r.doc.Run.Stages["intake"] = "completed"
	r.doc.Run.Stages["normalize"] = "pre-existing"
	r.doc.Run.Stages["checks"] = "pre-existing"
	if plan.Scope.AllowFailedGate {
		r.doc.Run.Overrides = map[string]string{"allow-failed-gate": "true"}
	}
	return nil
}
