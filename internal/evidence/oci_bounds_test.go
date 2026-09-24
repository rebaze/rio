package evidence

import (
	"github.com/rebaze/rio/internal/delivery"
	"runtime"
	"strings"
	"testing"
)

func TestProjectedIntentArraysBoundBeforeMaterialization(t *testing.T) {
	raw := []byte(`{"deliveries":[{"intent":{"destination":{"options":{"unknown":[` + strings.Repeat(`{},`, 100000) + `{}]}}}}]}`)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, e := Parse(raw, nil)
	runtime.ReadMemStats(&after)
	safe, ok := e.(*delivery.Error)
	if !ok || safe.Code != "size_limit" {
		t.Fatalf("projected intent was materialized before entry limit: %v", e)
	}
	if after.TotalAlloc-before.TotalAlloc > 8<<20 {
		t.Fatalf("large projected intent allocation: %d", after.TotalAlloc-before.TotalAlloc)
	}
}
