package evidence

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
)

func TestParseBoundsArraysBeforeMaterialization(t *testing.T) {
	for _, field := range []string{"evidence", "Evidence", "unexpected"} {
		t.Run(field, func(t *testing.T) {
			raw := []byte(`{"` + field + `":[` + strings.Repeat(`{},`, 999999) + `{}]}`)
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, e := Parse(raw, validateFixture)
			runtime.ReadMemStats(&after)
			if e == nil {
				t.Fatal("invalid oversized array accepted")
			}
			if used := after.TotalAlloc - before.TotalAlloc; used > 16<<20 {
				t.Fatalf("retained oversized/unknown array before refusal: allocated %d bytes for %d-byte input", used, len(raw))
			}
		})
	}
}
func TestParseCountLimitPrecedesOversizedElement(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
		count        int
	}{{"sources", `{"evidence":[`, MaxEvents + 1}, {"deliveries", `{"deliveries":[`, MaxJournals}, {"events", `{"deliveries":[{"events":[`, MaxEvents}} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(tc.prefix + strings.Repeat(`{},`, tc.count) + `not-valid-json`)
			_, e := Parse(raw, validateFixture)
			var safe *delivery.Error
			if !errors.As(e, &safe) || safe.Code != "size_limit" {
				t.Fatalf("excess element was visited before count bound: %v", e)
			}
		})
	}
}

func TestPreflightExactAndCumulativeCounts(t *testing.T) {
	for _, raw := range []string{`{"evidence":[` + strings.Repeat(`{},`, MaxEvents) + `{}]}`, `{"deliveries":[` + strings.Repeat(`{},`, MaxJournals-1) + `{}]}`, `{"deliveries":[{"events":[` + strings.Repeat(`{},`, 4999) + `{}]},{"events":[` + strings.Repeat(`{},`, 4999) + `{}]}]}`} {
		if e := preflightRecord([]byte(raw)); e != nil {
			t.Fatal("exact existing limit refused by preflight", e)
		}
	}
	raw := `{"deliveries":[{"events":[` + strings.Repeat(`{},`, 4999) + `{}]},{"events":[` + strings.Repeat(`{},`, 5000) + `broken`
	e := preflightRecord([]byte(raw))
	var safe *delivery.Error
	if !errors.As(e, &safe) || safe.Code != "size_limit" {
		t.Fatal("nested aggregate event cap checked after excess element", e)
	}
}
func TestPreflightUnknownNestedFieldBeforeItsValue(t *testing.T) {
	for _, prefix := range []string{`{"deliveries":[{"Events":`, `{"normalization":{"unexpected":`, `{"evidence":[{"Data":`} {
		raw := []byte(prefix + `[` + strings.Repeat(`{},`, 999999) + `{}]`)
		runtime.GC()
		var a, b runtime.MemStats
		runtime.ReadMemStats(&a)
		_, e := Parse(raw, validateFixture)
		runtime.ReadMemStats(&b)
		if e == nil || b.TotalAlloc-a.TotalAlloc > 1<<20 {
			t.Fatalf("unknown/case-alias nested field value materialized: %v allocation=%d", e, b.TotalAlloc-a.TotalAlloc)
		}
	}
}
