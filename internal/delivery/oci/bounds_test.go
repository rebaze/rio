package oci

import (
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"runtime"
	"strings"
	"testing"
)

func TestSavedOptionsPreallocation(t *testing.T) {
	for _, kind := range []string{"unknown", "manifest-layers"} {
		t.Run(kind, func(t *testing.T) {
			d := describe(t, "")
			s, ref := sourceRef()
			p, e := (Provider{}).Prepare(d, s, []delivery.PayloadRef{ref})
			if e != nil {
				t.Fatal(e)
			}
			d = p.Description
			if kind == "unknown" {
				d.Options = []byte(`{"unknown":[` + strings.Repeat(`{},`, 200000) + `{}]}`)
			} else {
				var m map[string]any
				json.Unmarshal(d.Options, &m)
				pub := m["publication"].(map[string]any)
				pub["manifestJSON"] = `{"layers":[` + strings.Repeat(`{},`, 100000) + `{}]}`
				d.Options, _ = json.Marshal(m)
			}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, _, e = ValidateDescription(d)
			runtime.ReadMemStats(&after)
			if e == nil {
				t.Fatal("malformed saved options")
			}
			if after.TotalAlloc-before.TotalAlloc > 8<<20 {
				t.Fatalf("allocated before refusal: %d", after.TotalAlloc-before.TotalAlloc)
			}
		})
	}
}
