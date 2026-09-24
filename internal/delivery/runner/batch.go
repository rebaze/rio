package runner

import (
	"context"
	"errors"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
)

type BatchItem struct {
	ExpectedReferences []delivery.Reference  `json:"expectedReferences,omitempty"`
	ArtifactID         string                `json:"artifactId"`
	Target             string                `json:"target"`
	Record             string                `json:"record"`
	State              string                `json:"state"`
	Source             *delivery.Source      `json:"source,omitempty"`
	Destination        *delivery.Description `json:"destination,omitempty"`
	Result             *Result               `json:"result,omitempty"`
	Error              *delivery.Error       `json:"error,omitempty"`
}
type BatchResult struct {
	SchemaVersion          int                   `json:"schemaVersion"`
	Operation              string                `json:"operation"`
	Outcome                string                `json:"outcome"`
	IndexSHA256            string                `json:"indexSHA256,omitempty"`
	ManifestSHA256         string                `json:"manifestSHA256,omitempty"`
	RequestMayHaveOccurred bool                  `json:"requestMayHaveOccurred"`
	Items                  []BatchItem           `json:"items"`
	UnusedRules            []delivery.UnusedRule `json:"unusedRules"`
	Error                  *delivery.Error       `json:"error,omitempty"`
	ExitCode               int                   `json:"-"`
}

func NewBatch(operation string, plan delivery.BatchPlan) BatchResult {
	r := BatchResult{SchemaVersion: 2, Operation: operation, Outcome: "error", IndexSHA256: plan.IndexSHA256, ManifestSHA256: plan.ManifestSHA256, Items: []BatchItem{}, UnusedRules: plan.UnusedRules}
	if r.UnusedRules == nil {
		r.UnusedRules = []delivery.UnusedRule{}
	}
	for _, j := range plan.Jobs {
		state := "unattempted"
		if operation == "plan" {
			state = "ready"
		}
		item := BatchItem{ArtifactID: j.ArtifactID, Target: j.Target, Record: j.Record, State: state, Error: j.Error, ExpectedReferences: j.ExpectedReferences}
		if len(j.Verified.Payloads()) > 0 {
			source := j.Verified.Source()
			item.Source = &source
		}
		if j.Description.Type != "" {
			d := j.Description
			item.Destination = &d
		}
		if j.Error != nil {
			item.State = "error"
		} else if item.Source == nil {
			item.State = "unattempted"
		}
		r.Items = append(r.Items, item)
	}
	return r
}
func BatchFailure(r BatchResult, e error, code int) (BatchResult, error) {
	var safe *delivery.Error
	if !errors.As(e, &safe) {
		safe = &delivery.Error{Code: "execution_failed", Message: "operation failed"}
	}
	r.Error = safe
	r.ExitCode = code
	return r, safe
}

// SubmitBatch owns all reservations and releases the unattempted suffix before return.
func SubmitBatch(ctx context.Context, r BatchResult, prepared []Prepared, reservations []*record.Reservation) (result BatchResult, err error) {
	result = r
	defer func() {
		for _, res := range reservations {
			if e := res.Close(); e != nil {
				result, err = BatchFailure(result, e, 3)
			}
		}
	}()
	// Defend this entry point as well as the CLI: a complete later intent must
	// never fail its known local validation after an earlier remote request.
	for i, p := range prepared {
		if _, e := PrepareIntent(p); e != nil {
			result.Items[i].State = "error"
			if safe, ok := e.(*delivery.Error); ok {
				result.Items[i].Error = safe
			}
			result.Outcome = "error"
			return BatchFailure(result, e, PreflightCode(e))
		}
	}
	accepted := 0
	for i, p := range prepared {
		p.Reservation = reservations[i]
		one, e := Submit(ctx, p, result.Items[i].Record)
		item := &result.Items[i]
		item.Result = &one
		item.State = one.Outcome
		item.Error = one.Error
		result.RequestMayHaveOccurred = result.RequestMayHaveOccurred || one.RequestMayHaveOccurred
		if e != nil {
			if !one.RequestMayHaveOccurred {
				item.State = "error"
			}
			result.Outcome = item.State
			if accepted > 0 {
				result.Outcome = "partial"
			} else if one.ExitCode == 3 {
				result.Outcome = "error"
			}
			return BatchFailure(result, e, one.ExitCode)
		}
		accepted++
	}
	result.Outcome = "accepted"
	return result, nil
}
