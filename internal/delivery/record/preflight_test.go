package record

import (
	"runtime"
	"strings"
	"testing"
)

func TestExpectedReferenceArrayPreallocation(t *testing.T) {
	raw := []byte(`{"schemaVersion":1,"sequence":0,"attemptId":"00000000000000000000000000000000","observedAt":"2026-09-24T12:00:00Z","kind":"intent","data":{"expectedReferences":[` + strings.Repeat(`{},`, 100000) + `{}]}}`)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, e := DecodeEvents([][]byte{raw})
	runtime.ReadMemStats(&after)
	if e == nil {
		t.Fatal("malformed expected refs accepted")
	}
	if after.TotalAlloc-before.TotalAlloc > 8<<20 {
		t.Fatalf("array allocated before refusal: %d", after.TotalAlloc-before.TotalAlloc)
	}
}
