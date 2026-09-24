// Package runner orders verified submission and journal updates independently of adapters.
package runner

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
)

type Prepared struct {
	ExpectedReferences []delivery.Reference
	ValidateIntent     func(record.Intent) error
	Verified           delivery.Verified
	Description        delivery.Description
	Intent             record.Intent
	Target             delivery.Target
	Reservation        *record.Reservation
}
type Result struct {
	ExpectedReferences     []delivery.Reference   `json:"expectedReferences,omitempty"`
	SchemaVersion          int                    `json:"schemaVersion"`
	Operation              string                 `json:"operation"`
	AttemptID              string                 `json:"attemptId,omitempty"`
	Record                 string                 `json:"record,omitempty"`
	Outcome                string                 `json:"outcome"`
	Source                 *delivery.Source       `json:"source,omitempty"`
	Destination            *delivery.Description  `json:"destination,omitempty"`
	Observations           []delivery.Observation `json:"observations"`
	Error                  *delivery.Error        `json:"error,omitempty"`
	RequestMayHaveOccurred bool                   `json:"requestMayHaveOccurred"`
	Persisted              bool                   `json:"persisted"`
	Acknowledgment         string                 `json:"acknowledgment,omitempty"`
	Verification           string                 `json:"verification,omitempty"`
	Activity               string                 `json:"activity,omitempty"`
	Journal                *record.Snapshot       `json:"journal,omitempty"`
	ExitCode               int                    `json:"-"`
}

func NewResult(operation, path string) Result {
	return Result{SchemaVersion: 1, Operation: operation, Record: path, Outcome: "unknown", Observations: []delivery.Observation{}}
}
func Failure(r Result, err error, code int) (Result, error) {
	var safe *delivery.Error
	if !errors.As(err, &safe) {
		safe = &delivery.Error{Code: "execution_failed", Message: "operation failed"}
	}
	r.Error = safe
	r.ExitCode = code
	return r, safe
}
func PreflightCode(err error) int {
	var e *delivery.Error
	if errors.As(err, &e) && e.Code == "persistence_failed" {
		return 3
	}
	return 2
}
func FromSnapshot(operation, path string, s record.Snapshot) Result {
	r := NewResult(operation, path)
	r.AttemptID = s.Events[0].AttemptID
	r.Source = &s.Intent.Source
	r.Destination = &s.Intent.Destination
	r.ExpectedReferences = append([]delivery.Reference(nil), s.Intent.ExpectedReferences...)
	r.Outcome = s.Disposition
	r.Acknowledgment = s.Disposition
	r.Observations = s.Observations
	r.Persisted = true
	for _, o := range s.Observations {
		if o.Kind == "content" {
			r.Verification = o.Value
		}
		if o.Kind == "activity" {
			r.Activity = o.Value
		}
	}
	return r
}
func Submit(ctx context.Context, p Prepared, path string) (r Result, err error) {
	r = NewResult("deliver", path)
	source := p.Verified.Source()
	r.Source = &source
	r.Destination = &p.Description
	r.ExpectedReferences = append([]delivery.Reference(nil), p.ExpectedReferences...)
	if p.Target == nil || len(p.Verified.Payloads()) == 0 {
		return Failure(r, delivery.Fail("invalid_prepared", "verified payload and target required"), 2)
	}
	intent, e := PrepareIntent(p)
	if e != nil {
		return Failure(r, e, PreflightCode(e))
	}
	var w *record.Writer
	if p.Reservation != nil {
		w, e = p.Reservation.Create(intent)
	} else {
		w, e = record.Create(path, intent)
	}
	if e != nil {
		return Failure(r, e, PreflightCode(e))
	}
	defer func() {
		if e := w.Close(); e != nil {
			r, err = Failure(r, e, 3)
		}
	}()
	s, e := w.Snapshot()
	if e != nil {
		return Failure(r, e, 3)
	}
	r.AttemptID = s.Events[0].AttemptID
	r.RequestMayHaveOccurred = true
	sub, submitErr := p.Target.Submit(ctx, p.Verified.Payloads())
	if sub.Disposition != "accepted" && sub.Disposition != "rejected" {
		sub.Disposition = "unknown"
	}
	if sub.References == nil {
		sub.References = []delivery.Reference{}
	}
	if sub.Observations == nil {
		sub.Observations = []delivery.Observation{}
	}
	r.Outcome = sub.Disposition
	r.Acknowledgment = sub.Disposition
	r.Observations = sub.Observations
	for _, o := range sub.Observations {
		if o.Kind == "content" {
			r.Verification = o.Value
		}
	}
	b, e := json.Marshal(sub)
	if e != nil {
		return Failure(r, delivery.Fail("persistence_failed", "remote disposition observed; result not saved"), 3)
	}
	if e = w.Append("submission", b); e != nil {
		return Failure(r, delivery.Fail("persistence_failed", "remote disposition observed; result not durably saved"), 3)
	}
	r.Persisted = true
	switch sub.Disposition {
	case "accepted":
		return r, nil
	case "rejected":
		return Failure(r, delivery.Fail("upload_rejected", "receiver rejected upload"), 5)
	default:
		if submitErr == nil {
			submitErr = delivery.Fail("remote_unknown", "submission outcome unknown")
		}
		return Failure(r, submitErr, 4)
	}
}

// Retry validates a locked snapshot already read by the CLI. Its path is only a hint.
func Retry(prior record.Snapshot, v delivery.Verified, d delivery.Description, policyEqual bool, path string) (*record.Retry, error) {
	s := v.Source()
	p := prior.Intent.Source
	if p.IndexSHA256 != s.IndexSHA256 || p.OutputSHA256 != s.OutputSHA256 || p.ArtifactID != s.ArtifactID || p.AllowFailedGate != s.AllowFailedGate || prior.Intent.Destination.Type != d.Type || !delivery.JSONEqual(prior.Intent.Destination.Identity, d.Identity) || !policyEqual {
		return nil, delivery.Fail("retry_mismatch", "retry requires same source, target and policies")
	}
	return &record.Retry{AttemptID: prior.Events[0].AttemptID, SHA256: prior.SHA256, PathHint: path}, nil
}

// PrepareIntent assembles authoritative verified fields and checks the exact
// complete journal envelope before any batch attempt may begin.
func PrepareIntent(p Prepared) (record.Intent, error) {
	intent := p.Intent
	intent.Source = p.Verified.Source()
	intent.Destination = p.Description
	intent.ExpectedReferences = append([]delivery.Reference(nil), p.ExpectedReferences...)
	intent.Payloads = []delivery.PayloadRef{}
	for _, payload := range p.Verified.Payloads() {
		intent.Payloads = append(intent.Payloads, payload.Ref())
	}
	if p.ValidateIntent != nil {
		if e := p.ValidateIntent(intent); e != nil {
			return record.Intent{}, e
		}
	}
	if e := record.CheckIntent(intent); e != nil {
		return record.Intent{}, e
	}
	return intent, nil
}
