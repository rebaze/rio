package runner

import (
	"context"
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"slices"
	"time"
)

func Reconcile(ctx context.Context, w *record.Writer, target delivery.Observer, configSHA256 string, wait time.Duration) (Result, error) {
	return reconcile(ctx, w, target, configSHA256, wait, pause)
}
func pause(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func reconcile(ctx context.Context, w *record.Writer, target delivery.Observer, configSHA256 string, wait time.Duration, sleep func(context.Context, time.Duration) error) (Result, error) {
	r := NewResult("reconcile", "")
	s, e := w.Snapshot()
	if e != nil {
		return Failure(r, e, 2)
	}
	r = FromSnapshot("reconcile", "", s)
	if wait < 0 || wait > 10*time.Minute {
		return Failure(r, delivery.Fail("invalid_wait", "wait must be positive and at most 10m"), 2)
	}
	content := delivery.HasCapability(s.Intent.Destination, "observe-content")
	if content && wait != 0 {
		return Failure(r, delivery.Fail("invalid_wait", "content observations do not poll"), 2)
	}
	refs := slices.Clone(s.References)
	if len(refs) == 0 && content {
		refs = slices.Clone(s.Intent.ExpectedReferences)
	}
	if wait > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, wait)
		defer cancel()
	}
	for {
		if ctx.Err() != nil {
			return Failure(r, delivery.Fail("observation_deadline", "observation deadline or cancellation; prior evidence retained"), 4)
		}
		timeout := 30 * time.Second
		if content {
			timeout = 5 * time.Minute
		}
		requestCtx, cancel := context.WithTimeout(ctx, timeout)
		r.RequestMayHaveOccurred = true
		o, observeErr := target.Observe(requestCtx, refs)
		cancel()
		b, e := json.Marshal(record.Reconciliation{Observation: o, ConfigSHA256: configSHA256})
		r.Observations = append(r.Observations, o)
		if o.Kind == "activity" {
			r.Activity = o.Value
			r.Outcome = o.Value
		} else if o.Kind == "content" {
			r.Verification = o.Value
			r.Outcome = o.Value
		} else {
			r.Outcome = "unavailable"
		}
		if e != nil {
			return Failure(r, delivery.Fail("persistence_failed", "observation not saved"), 3)
		}
		if e = w.Append("reconciliation", b); e != nil {
			r.Persisted = false
			return Failure(r, delivery.Fail("persistence_failed", "observation not durably saved"), 3)
		}
		if o.Kind == "content" && o.Value != "verified" && observeErr == nil {
			observeErr = delivery.Fail("observation_unavailable", "content verification incomplete")
		}
		if observeErr == nil && (wait == 0 || o.Value == "not-observed") {
			return r, nil
		}
		if wait == 0 || (observeErr != nil && o.Code != "transport_unavailable" && o.Code != "query_transient") {
			if observeErr == nil {
				observeErr = delivery.Fail("observation_unavailable", "activity unavailable")
			}
			return Failure(r, observeErr, 4)
		}
		if e = sleep(ctx, 3*time.Second); e != nil {
			return Failure(r, delivery.Fail("observation_deadline", "observation deadline or cancellation; prior evidence retained"), 4)
		}
	}
}
