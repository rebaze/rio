package receipt

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func TestReceiptRefusesContradictoryDeliveryFacts(t *testing.T) {
	cases := map[string]func(*Document){
		"different submitted bytes": func(d *Document) { d.Deliveries[0].Submitted = []Bytes{{SHA256: strings.Repeat("c", 64), Size: 234}} },
		"accepted without acknowledgment": func(d *Document) {
			d.Deliveries[0].Responses[0].Kind = "content"
			d.Deliveries[0].Responses[0].Value = "verified"
		},
		"rejected but accepted response": func(d *Document) { d.Deliveries[0].State = "rejected" },
		"cross-adapter reference": func(d *Document) {
			d.Deliveries[0].Responses[0].References[0] = Reference{Kind: "oci:blob", Value: "sha256:" + strings.Repeat("a", 64)}
		},
		"invalid event token":      func(d *Document) { d.Deliveries[0].Responses[0].References[0].Value = "unbounded server text" },
		"zero bytes wrong digest":  func(d *Document) { d.Artifacts[0].Input.Size = 0 },
		"response before attempt":  func(d *Document) { d.Deliveries[0].Responses[0].ObservedAt = "2026-09-27T11:59:59Z" },
		"fake response kind":       func(d *Document) { d.Deliveries[0].Responses[0].Kind = "ingested" },
		"response without request": func(d *Document) { d.Deliveries[0].State = "unknown"; d.Deliveries[0].RequestMayHaveOccurred = false },
		"negative reason": func(d *Document) {
			d.Artifacts[0].Changes = &Changes{Bulk: []BulkChange{{Operation: "repair-purl/p2", Scope: "top-level", Evaluated: 1, Reasons: map[string]int{"unmapped": -1}}}}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			d := fixture()
			d.Deliveries[0].Intended = []Bytes{{ArtifactOutput: "api"}}
			change(&d)
			if _, e := Marshal(d); e == nil {
				t.Fatal("accepted contradictory facts")
			}
		})
	}
}
func TestCountBoundsRefuseBeforeRetainingHugeCollections(t *testing.T) {
	raw, _ := Marshal(fixture())
	raw = bytes.Replace(raw, []byte(`"run": {`), []byte(`"exclusions": [`+strings.Repeat(`{"reason":"x"},`, 200000)+`{"reason":"x"}], "run": {`), 1)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, e := Parse(raw)
	runtime.ReadMemStats(&after)
	if e == nil {
		t.Fatal("oversized count accepted")
	}
	if after.TotalAlloc-before.TotalAlloc > 8<<20 {
		t.Fatalf("retained collection before refusing count: %d bytes", after.TotalAlloc-before.TotalAlloc)
	}
}
func TestStringAndDepthBounds(t *testing.T) {
	d := fixture()
	d.Artifacts[0].Input.Path = strings.Repeat("x", 16385)
	if _, e := Marshal(d); e == nil {
		t.Fatal("unbounded reference string")
	}
	raw, _ := Marshal(fixture())
	nested := strings.Repeat(`[`, 65) + `0` + strings.Repeat(`]`, 65)
	raw = bytes.Replace(raw, []byte(`"run": {`), []byte(`"deep": `+nested+`, "run": {`), 1)
	if _, e := Parse(raw); e == nil {
		t.Fatal("deep object accepted")
	}
}
