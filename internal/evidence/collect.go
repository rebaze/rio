package evidence

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/index"
)

func invalid() error {
	return delivery.Fail("invalid_evidence", "record structure or evidence relationship")
}
func limitError() error { return delivery.Fail("size_limit", "consolidated record limit") }
func Collect(indexPath string, journalPaths []string, toolVersion string, validate Validator, retryPolicy ...RetryValidator) (Document, error) {
	if len(journalPaths) > MaxJournals {
		return Document{}, limitError()
	}
	raw, e := delivery.ReadBounded(indexPath, delivery.IndexLimit)
	if e != nil {
		return Document{}, e
	}
	if _, e = delivery.ParseIndex(raw); e != nil {
		return Document{}, e
	}
	remaining := SourceLimit - int64(len(raw))
	events := 0
	captures := make([]record.Capture, 0, len(journalPaths))
	for _, path := range journalPaths {
		c, e := record.CaptureRead(path, remaining)
		if e != nil {
			return Document{}, e
		}
		events += len(c.RawEvents)
		if events > MaxEvents {
			return Document{}, limitError()
		}
		for _, b := range c.RawEvents {
			remaining -= int64(len(b))
		}
		captures = append(captures, c)
	}
	return assemble(raw, captures, toolVersion, validate, retryPolicy...)
}
func source(id, kind string, b []byte) SourceDocument {
	return SourceDocument{id, kind, "application/json", delivery.Digest(b), int64(len(b)), "base64", base64.StdEncoding.EncodeToString(b)}
}
func eventID(id string, n int) string { return fmt.Sprintf("delivery/%s/%020d", id, n) }
func assemble(raw []byte, captures []record.Capture, version string, validate Validator, retryPolicy ...RetryValidator) (Document, error) {
	var d Document
	if version == "" || int64(len(raw)) > delivery.IndexLimit || len(captures) > MaxJournals {
		return d, invalid()
	}
	idx, e := delivery.ParseIndex(raw)
	if e != nil {
		return d, e
	}
	indexView, e := canonicalJSON(raw)
	if e != nil {
		return d, e
	}
	sort.Slice(captures, func(i, j int) bool {
		a, b := captures[i].Snapshot, captures[j].Snapshot
		if a.Intent.Source.ArtifactID != b.Intent.Source.ArtifactID {
			return a.Intent.Source.ArtifactID < b.Intent.Source.ArtifactID
		}
		return a.Events[0].AttemptID < b.Events[0].AttemptID
	})
	d = Document{SchemaVersion: 1, Kind: "rio-evidence-record", Tool: index.Tool{Name: "rio", Version: version}, Normalization: Normalization{"normalization-index", delivery.Digest(raw), indexView, "not-performed"}, Deliveries: []Delivery{}, Evidence: []SourceDocument{source("normalization-index", "normalization-index", raw)}, Coverage: Coverage{DeliverySelection: "explicit", SelectedDeliveryCount: len(captures), ArtifactIDsWithoutSelectedDeliveries: []string{}, RetryAttemptIDsNotIncluded: []string{}, SBOMFiles: "not-included", NormalizationInputs: "not-included", NormalizationStatements: "not-included", Signatures: "not-included", WorkerIdentity: "not-recorded", AuthenticatedProducerIdentity: "not-established", CollectionNotes: []CollectionNote{}}}
	artifacts := map[string]index.Artifact{}
	for _, a := range idx.Artifacts {
		artifacts[a.ID] = a
	}
	attempts := map[string]record.Capture{}
	selected := map[string]bool{}
	total := int64(len(raw))
	eventCount := 0
	for _, c := range captures {
		s := c.Snapshot
		if len(s.Events) == 0 || len(c.RawEvents) != len(s.Events) {
			return Document{}, invalid()
		}
		id := s.Events[0].AttemptID
		if _, ok := attempts[id]; ok {
			return Document{}, delivery.Fail("duplicate_attempt", "selected journals contain repeated attempt")
		}
		attempts[id] = c
		a, ok := artifacts[s.Intent.Source.ArtifactID]
		v := s.Intent.Source
		if !ok || v.IndexSHA256 != d.Normalization.IndexSHA256 || v.OutputSHA256 != a.Output.SHA256 || v.Gate != string(a.Gate) || v.SchemaValidated != a.SchemaValidated {
			return Document{}, delivery.Fail("evidence_mismatch", "journal source does not match exact index")
		}
		if validate != nil {
			if e = validate(s); e != nil {
				return Document{}, e
			}
		}
		selected[a.ID] = true
		x := Delivery{AttemptID: id, ArtifactID: a.ID, Intent: s.Intent, Events: s.Events, Journal: Journal{s.SHA256, len(s.Events), s.Events[len(s.Events)-1].Sequence}, EvidenceIDs: []string{}, Summary: Summary{Acknowledgment: s.Disposition}}
		for n, b := range c.RawEvents {
			total += int64(len(b))
			eventCount++
			if total > SourceLimit || eventCount > MaxEvents {
				return Document{}, limitError()
			}
			eid := eventID(id, n)
			x.EvidenceIDs = append(x.EvidenceIDs, eid)
			d.Evidence = append(d.Evidence, source(eid, "delivery-event", b))
		}
		for _, ev := range s.Events {
			observations := []delivery.Observation{}
			if ev.Kind == "submission" {
				var sub delivery.Submission
				_ = delivery.DecodeJSON(ev.Data, &sub, true)
				observations = sub.Observations
			}
			if ev.Kind == "reconciliation" {
				var r record.Reconciliation
				_ = delivery.DecodeJSON(ev.Data, &r, true)
				observations = append(observations, r.Observation)
			}
			for _, o := range observations {
				ob := &Observation{ev.Sequence, ev.ObservedAt, o}
				x.Summary.LastObservation = ob
				if o.Kind == "activity" {
					x.Summary.LatestActivity = ob
				}
			}
		}
		if len(s.OrphanTemps) > 0 {
			d.Coverage.CollectionNotes = append(d.Coverage.CollectionNotes, CollectionNote{"orphan-temporary-files", id, len(s.OrphanTemps), "collector"})
		}
		// RawMessage fields were validated by the shared readers, which may
		// escape HTML while binding JSON. Canonicalize only the readable copies;
		// evidence data remains the exact captured bytes.
		x.Intent.Destination.Identity, _ = canonicalJSON(x.Intent.Destination.Identity)
		x.Intent.Destination.Options, _ = canonicalJSON(x.Intent.Destination.Options)
		x.Events = append([]record.Event{}, x.Events...)
		for n := range x.Events {
			x.Events[n].Data, _ = canonicalJSON(x.Events[n].Data)
		}
		for _, o := range []*Observation{x.Summary.LatestActivity, x.Summary.LastObservation} {
			if o != nil && o.Observation.Details != nil {
				o.Observation.Details, _ = canonicalJSON(o.Observation.Details)
			}
		}
		d.Deliveries = append(d.Deliveries, x)
	}
	missing := map[string]bool{}
	for id, c := range attempts {
		retry := c.Snapshot.Intent.Retry
		if retry == nil {
			continue
		}
		if retry.AttemptID == id {
			return Document{}, delivery.Fail("retry_mismatch", "self retry")
		}
		prior, ok := attempts[retry.AttemptID]
		if !ok {
			missing[retry.AttemptID] = true
			continue
		}
		if !compatible(c.Snapshot.Intent, prior.Snapshot.Intent, retryPolicy...) {
			return Document{}, delivery.Fail("retry_mismatch", "retry source target or policies differ")
		}
		h := sha256.New()
		matched := false
		for n, b := range prior.RawEvents {
			h.Write(b)
			if hex.EncodeToString(h.Sum(nil)) == retry.SHA256 {
				prefix, e := record.DecodeEvents(prior.RawEvents[:n+1])
				if e != nil {
					return Document{}, e
				}
				if validate != nil {
					if e = validate(prefix); e != nil {
						return Document{}, e
					}
				}
				matched = true
				break
			}
		}
		if !matched {
			return Document{}, delivery.Fail("retry_mismatch", "prior committed prefix not found")
		}
	}
	// Detect cycles explicitly, independent of whether a digest mismatch would also refuse.
	for id := range attempts {
		seen := map[string]bool{}
		for next := id; next != ""; {
			if seen[next] {
				return Document{}, delivery.Fail("retry_mismatch", "cyclic retry")
			}
			seen[next] = true
			c, ok := attempts[next]
			if !ok || c.Snapshot.Intent.Retry == nil {
				break
			}
			next = c.Snapshot.Intent.Retry.AttemptID
		}
	}
	for id := range artifacts {
		if !selected[id] {
			d.Coverage.ArtifactIDsWithoutSelectedDeliveries = append(d.Coverage.ArtifactIDsWithoutSelectedDeliveries, id)
		}
	}
	for id := range missing {
		d.Coverage.RetryAttemptIDsNotIncluded = append(d.Coverage.RetryAttemptIDsNotIncluded, id)
	}
	sort.Strings(d.Coverage.ArtifactIDsWithoutSelectedDeliveries)
	sort.Strings(d.Coverage.RetryAttemptIDsNotIncluded)
	d.validator = validate
	if len(retryPolicy) > 0 {
		d.retryValidator = retryPolicy[0]
	}
	return d, nil
}
func compatible(a, b record.Intent, policy ...RetryValidator) bool {
	if a.Source != b.Source || !reflect.DeepEqual(a.Payloads, b.Payloads) || a.Destination.Type != b.Destination.Type || !jsonEqual(a.Destination.Identity, b.Destination.Identity) {
		return false
	}
	if len(policy) > 0 && policy[0] != nil {
		return policy[0](a, b) == nil
	}
	return jsonEqual(a.Destination.Options, b.Destination.Options)
}
