package cli

import (
	"path/filepath"
	"reflect"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/dtrack"
	"github.com/rebaze/rio/internal/delivery/oci"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/receipt"
)

type recoveryAttempt struct {
	AttemptID string `json:"attemptId"`
	Journal   string `json:"journal"`
}
type recoveryReconcile struct {
	Journal     string `json:"journal"`
	PriorSHA256 string `json:"priorSHA256"`
	EventOffset int    `json:"eventOffset"`
}

const recoveryBudget int64 = 64 << 20

// recoverInvocation reads explicit local recovery state. It never builds a
// client, resolves credentials, removes locks, or replays requests. A validated
// journal prefix does not establish that the invocation completed.
func recoverInvocation(dir string) (receipt.Document, error) {
	d, e := receipt.ReadCheckpoint(dir)
	if e != nil {
		return d, e
	}
	if d.Run.Outcome != "incomplete" {
		return d, nil
	}
	d.Run.FinishedAt = ""
	if len(d.Deliveries) == 0 {
		return d, nil
	}
	raw, e := delivery.ReadBounded(filepath.Join(dir, ".internal", "attempts.json"), receipt.MaxBytes)
	if e != nil {
		markRecoveryGaps(&d, "attempt_mapping_unavailable")
		return d, nil
	}
	if d.Run.Operation == "reconcile" {
		return recoverReconcile(d, raw)
	}
	var attempts []recoveryAttempt
	if e = delivery.DecodeJSON(raw, &attempts, true); e != nil || len(attempts) != len(d.Deliveries) || len(attempts) > receipt.MaxItems {
		return d, delivery.Fail("invalid_recovery", "attempt mapping")
	}
	budget := recoveryBudget
	for i, a := range attempts {
		v := &d.Deliveries[i]
		if a.AttemptID == "" || a.AttemptID != v.AttemptID {
			return d, delivery.Fail("invalid_recovery", "attempt binding")
		}
		s, e := record.RecoverySnapshot(a.Journal, min(budget, receipt.MaxBytes))
		if e != nil {
			if len(v.Responses) == 0 {
				recoveryGap(v, "journal_unavailable")
			} else {
				d.Exceptions = append(d.Exceptions, "journal-unavailable-checkpoint-retained")
			}
			continue
		}
		for _, event := range s.Events {
			budget -= int64(len(event.Data)) + 256
		}
		if budget < 0 {
			return d, delivery.Fail("size_limit", "recovery journal budget")
		}
		if e = validateSnapshot(s); e != nil {
			return d, e
		}
		if len(s.Events) == 0 || s.Events[0].AttemptID != a.AttemptID || s.Intent.Source.ArtifactID != v.ArtifactID || s.Intent.Binding != v.Target {
			return d, delivery.Fail("invalid_recovery", "journal attempt identity")
		}
		target, project, transport, e := compactDestination(s.Intent.Destination)
		if e != nil {
			return d, e
		}
		if !reflect.DeepEqual(target, d.Targets[v.Target]) || !reflect.DeepEqual(project, v.Project) || transport.Scheme != v.Transport.Scheme || transport.CertificateVerification != v.Transport.CertificateVerification {
			return d, delivery.Fail("invalid_recovery", "journal destination")
		}
		intended := s.Intent.Payloads
		if s.Intent.Destination.Type == "oci" {
			intended, e = oci.PublicationBodies(s.Intent.Destination)
			if e != nil {
				return d, e
			}
		}
		if !sameRecoveredPayloads(d, *v, intended) {
			return d, delivery.Fail("invalid_recovery", "journal payload binding")
		}
		if len(v.Responses) > 0 {
			continue
		} // Independently committed live facts remain authoritative.
		// An intent was persisted before calling the adapter. It proves neither
		// absence nor acceptance of a request whose response was not committed.
		v.State = "unknown"
		v.RequestMayHaveOccurred = true
		v.Responses = nil
		v.Submitted = nil
		v.ErrorCode = "response_unavailable"
		for _, event := range s.Events {
			if event.Kind != "submission" {
				continue
			}
			var sub delivery.Submission
			if e = delivery.DecodeJSON(event.Data, &sub, true); e != nil {
				return d, e
			}
			v.State = sub.Disposition
			v.ErrorCode = ""
			for _, o := range sub.Observations {
				if e = appendRecoveredObservation(v, target.Type, o, event.ObservedAt); e != nil {
					return d, e
				}
			}
			for _, ref := range sub.Submitted {
				v.Submitted = append(v.Submitted, compactBody(d, v.ArtifactID, ref))
			}
		}
	}
	d.Exceptions = append(d.Exceptions, "recovered-incomplete-invocation")
	return d, receipt.Validate(d)
}
func sameRecoveredPayloads(d receipt.Document, v receipt.Delivery, ps []delivery.PayloadRef) bool {
	if len(v.Intended) != len(ps) {
		return false
	}
	for i, b := range v.Intended {
		if b.ArtifactOutput != "" {
			found := false
			for _, a := range d.Artifacts {
				if a.ID == b.ArtifactOutput && a.Output != nil {
					b = *a.Output
					found = true
				}
			}
			if !found {
				return false
			}
		}
		if b.SHA256 != ps[i].SHA256 || b.Size != ps[i].Size {
			return false
		}
	}
	return true
}
func recoveryGap(v *receipt.Delivery, code string) {
	v.State = "evidence-gap"
	v.RequestMayHaveOccurred = true
	v.ErrorCode = code
}
func markRecoveryGaps(d *receipt.Document, code string) {
	for i := range d.Deliveries {
		recoveryGap(&d.Deliveries[i], code)
	}
	d.Exceptions = append(d.Exceptions, "recovered-incomplete-invocation")
}
func appendRecoveredObservation(v *receipt.Delivery, kind string, o delivery.Observation, observedAt string) error {
	response := receipt.Response{Kind: o.Kind, Value: o.Value, Code: o.Code, HTTPStatus: o.HTTPStatus, ObservedAt: observedAt}
	for _, ref := range o.References {
		response.References = append(response.References, receipt.Reference{Kind: ref.Kind, Value: ref.Value})
	}
	v.Responses = append(v.Responses, response)
	if kind == "oci" {
		facts, e := oci.ReadTLS(o)
		if e != nil {
			return e
		}
		if facts != nil {
			observed := facts.Observed
			v.Transport.TLSObserved = &observed
		}
	}
	if kind == "dependency-track" {
		facts, e := dtrack.ReadTLS(o)
		if e != nil {
			return e
		}
		if facts != nil {
			observed := facts.Observed
			v.Transport.TLSObserved = &observed
		}
	}
	return nil
}
func recoverReconcile(d receipt.Document, raw []byte) (receipt.Document, error) {
	var m recoveryReconcile
	if e := delivery.DecodeJSON(raw, &m, true); e != nil || len(d.Deliveries) != 1 || m.EventOffset < 1 || !delivery.ValidDigest(m.PriorSHA256) {
		return d, delivery.Fail("invalid_recovery", "reconciliation mapping")
	}
	c, e := record.RecoveryCapture(m.Journal, recoveryBudget)
	if e != nil {
		markRecoveryGaps(&d, "journal_unavailable")
		return d, nil
	}
	if e = validateSnapshot(c.Snapshot); e != nil {
		return d, e
	}
	if m.EventOffset > len(c.RawEvents) {
		return d, delivery.Fail("invalid_recovery", "prior event prefix")
	}
	prior, e := record.DecodeEvents(c.RawEvents[:m.EventOffset])
	if e != nil || prior.SHA256 != m.PriorSHA256 || d.Run.Prior == nil || d.Run.Prior.SHA256 != m.PriorSHA256 {
		return d, delivery.Fail("invalid_recovery", "prior digest")
	}
	v := &d.Deliveries[0]
	// Keep live checkpoint observations when journal persistence failed. Replace
	// them only when a longer durable prefix is available; do not duplicate them.
	var committed []record.Event
	for _, event := range c.Snapshot.Events[m.EventOffset:] {
		if event.Kind != "reconciliation" {
			return d, delivery.Fail("invalid_recovery", "unexpected invocation event")
		}
		committed = append(committed, event)
	}
	if len(committed) > len(v.Responses) {
		v.Responses = nil
		for _, event := range committed {
			var rec record.Reconciliation
			if e = delivery.DecodeJSON(event.Data, &rec, true); e != nil {
				return d, e
			}
			if e = appendRecoveredObservation(v, d.Targets[v.Target].Type, rec.Observation, event.ObservedAt); e != nil {
				return d, e
			}
		}
	}
	if len(v.Responses) == 0 {
		recoveryGap(v, "observation_unavailable")
	}
	d.Exceptions = append(d.Exceptions, "recovered-incomplete-invocation")
	return d, receipt.Validate(d)
}
