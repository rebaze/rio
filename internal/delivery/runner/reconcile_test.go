package runner

import (
	"context"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"path/filepath"
	"testing"
	"time"
)

type fakeObserver struct {
	values []string
	calls  int
}

func (f *fakeObserver) Observe(context.Context, []delivery.Reference) (delivery.Observation, error) {
	v := f.values[f.calls]
	f.calls++
	o := delivery.Observation{Kind: "activity", Value: v, Origin: "receiver", Code: "activity_observed", References: []delivery.Reference{}}
	if v == "unavailable" {
		o.Kind = "unavailable"
		o.Code = "query_transient"
		o.HTTPStatus = 500
		return o, delivery.Fail("query_transient", "unavailable")
	}
	return o, nil
}
func TestReconcilePolling(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		wait   time.Duration
		exit   int
	}{{"single", []string{"processing"}, 0, 0}, {"finished", []string{"processing", "not-observed"}, time.Minute, 0}, {"transient", []string{"unavailable", "not-observed"}, time.Minute, 0}, {"deadline", []string{"processing"}, time.Nanosecond, 4}} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "journal")
			prepared := prepared(t, p, false)
			if _, e := Submit(context.Background(), prepared, p); e != nil {
				t.Fatal(e)
			}
			w, e := record.Open(p)
			if e != nil {
				t.Fatal(e)
			}
			defer w.Close()
			f := &fakeObserver{values: tc.values}
			r, _ := reconcile(context.Background(), w, f, prepared.Intent.ConfigSHA256, tc.wait, func(context.Context, time.Duration) error { return nil })
			if r.ExitCode != tc.exit || r.Acknowledgment != "accepted" {
				t.Fatal(r)
			}
			if tc.name != "deadline" && f.calls != len(tc.values) {
				t.Fatal(f.calls)
			}
			s, e := w.Snapshot()
			if e != nil {
				t.Fatal(e)
			}
			if len(s.Events) != 2+f.calls {
				t.Fatal("observations not persisted")
			}
		})
	}
}
