package cli

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/dtrack"
	"github.com/rebaze/rio/internal/delivery/oci"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/delivery/runner"
	"github.com/rebaze/rio/internal/receipt"
)

func (r *invocation) prepareReconcile(s record.Snapshot, journal string) error {
	prior := &receipt.Prior{AttemptID: s.Events[0].AttemptID, SHA256: s.SHA256}
	r.doc.Run.Prior = prior
	r.doc.Run.Stages["intake"] = "pre-existing"
	r.doc.Run.Stages["normalize"] = "pre-existing"
	r.doc.Run.Stages["checks"] = "pre-existing"
	// No SBOM bytes are read in a reconciliation. Do not borrow the prior run's
	// byte consumption or normalization claims as work of this invocation.
	r.doc.Artifacts = []receipt.Artifact{{ID: s.Intent.Source.ArtifactID, State: "not-attempted", PreExisting: true}}
	target, project, transport, e := compactDestination(s.Intent.Destination)
	if e != nil {
		return e
	}
	r.doc.Targets = map[string]receipt.Target{s.Intent.Binding: target}
	id := make([]byte, 16)
	if _, e = rand.Read(id); e != nil {
		return e
	}
	r.doc.Deliveries = []receipt.Delivery{{ArtifactID: s.Intent.Source.ArtifactID, Target: s.Intent.Binding, Project: project, AttemptID: fmt.Sprintf("%x", id), Prior: prior, State: "unattempted", Transport: transport}}
	raw, e := json.Marshal(struct {
		Journal     string `json:"journal"`
		PriorSHA256 string `json:"priorSHA256"`
		EventOffset int    `json:"eventOffset"`
	}{journal, s.SHA256, len(s.Events)})
	if e != nil {
		return e
	}
	if e = r.store.WriteRecovery(raw); e != nil {
		return e
	}
	return r.store.Checkpoint(r.doc)
}
func (r *invocation) reconcileHooks() runner.ReconcileHooks {
	return runner.ReconcileHooks{
		Before: func() error {
			v := &r.doc.Deliveries[0]
			v.State = "evidence-gap"
			v.RequestMayHaveOccurred = true
			return r.store.Checkpoint(r.doc)
		},
		After: func(o delivery.Observation, attemptedAt, observedAt string) error {
			v := &r.doc.Deliveries[0]
			v.State = "observed"
			if o.Kind == "unavailable" || o.Value == "unavailable" {
				v.State = "unavailable"
			}
			if v.AttemptedAt == "" {
				v.AttemptedAt = attemptedAt
			}
			response := receipt.Response{Kind: o.Kind, Value: o.Value, Code: o.Code, HTTPStatus: o.HTTPStatus, AttemptedAt: attemptedAt, ObservedAt: observedAt}
			for _, ref := range o.References {
				response.References = append(response.References, receipt.Reference{Kind: ref.Kind, Value: ref.Value})
			}
			v.Responses = append(v.Responses, response)
			if r.doc.Targets[v.Target].Type == "oci" {
				facts, e := oci.ReadTLS(o)
				if e != nil {
					return e
				}
				if facts != nil {
					observed := facts.Observed
					v.Transport.TLSObserved = &observed
				}
			}
			if r.doc.Targets[v.Target].Type == "dependency-track" {
				facts, e := dtrack.ReadTLS(o)
				if e != nil {
					return e
				}
				if facts != nil {
					observed := facts.Observed
					v.Transport.TLSObserved = &observed
				}
			}
			return r.store.Checkpoint(r.doc)
		},
	}
}
