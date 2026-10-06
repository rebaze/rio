package record

import (
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"path/filepath"
	"testing"
)

func TestExpectedReferencesAndIntentOnlyTransition(t *testing.T) {
	for _, bad := range []string{"", "kind", "value", "duplicate"} {
		t.Run(bad, func(t *testing.T) {
			i := intent()
			i.Destination.Capabilities = append(i.Destination.Capabilities, "observe-content")
			i.ExpectedReferences = []delivery.Reference{{Kind: "object", Value: "immutable"}}
			switch bad {
			case "kind":
				i.ExpectedReferences[0].Kind = ""
			case "value":
				i.ExpectedReferences[0].Value = ""
			case "duplicate":
				i.ExpectedReferences = append(i.ExpectedReferences, i.ExpectedReferences[0])
			}
			w, e := Create(filepath.Join(t.TempDir(), "record"), i)
			if bad != "" {
				if e == nil {
					w.Close()
					t.Fatal("bad expected refs accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer w.Close()
			for _, kind := range []string{"activity", "content"} {
				o := delivery.Observation{Kind: kind, Value: "verified", Origin: "receiver", Code: "observed", References: []delivery.Reference{}}
				if kind == "activity" {
					o.Value = "processing"
				}
				b, _ := json.Marshal(Reconciliation{Observation: o, ConfigSHA256: i.ConfigSHA256})
				e = w.Append("reconciliation", b)
				if (e == nil) != (kind == "content") {
					t.Fatal(kind, e)
				}
			}
			if e = w.Append("submission", submission()); e == nil {
				t.Fatal("late submission")
			}
			s, e := w.Snapshot()
			if e != nil || s.Disposition != "unknown" || len(s.Events) != 2 {
				t.Fatal(s, e)
			}
		})
	}
}
