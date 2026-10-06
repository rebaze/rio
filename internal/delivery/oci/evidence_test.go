package oci

import (
	"context"
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/delivery/runner"
	"path/filepath"
	"strings"
	"testing"
)

func acceptedSnapshot(t *testing.T) record.Snapshot {
	t.Helper()
	s := newRegistry(t)
	v, _ := verified(t)
	c := submitClient(t, s, v, nil)
	p := runner.Prepared{Verified: v, Description: description(c.options, "registry"), ExpectedReferences: expected(c.options), ValidateIntent: ValidateIntent, Intent: record.Intent{RioVersion: "test", Binding: "registry", ConfigSHA256: strings.Repeat("a", 64)}, Target: c}
	path := filepath.Join(t.TempDir(), "journal")
	if _, e := runner.Submit(context.Background(), p, path); e != nil {
		t.Fatal(e)
	}
	snap, e := record.Read(path)
	if e != nil {
		t.Fatal(e)
	}
	return snap
}
func TestSavedOCIContradictions(t *testing.T) {
	base := acceptedSnapshot(t)
	for _, mode := range []string{"unknown-code", "remote-500", "local-receipt", "false-began", "impossible-phase", "unrelated-content", "unknown-accepted", "invented-already-present", "bad-capabilities", "bad-expectations"} {
		t.Run(mode, func(t *testing.T) {
			var s record.Snapshot
			b, _ := json.Marshal(base)
			json.Unmarshal(b, &s)
			var sub delivery.Submission
			json.Unmarshal(s.Events[1].Data, &sub)
			o := &sub.Observations[0]
			var d details
			json.Unmarshal(o.Details, &d)
			switch mode {
			case "unknown-code":
				o.Code = "invented"
			case "remote-500":
				o.HTTPStatus = 500
			case "local-receipt":
				o.Origin = "local"
			case "false-began":
				d.OCI.PublicationBegan = false
			case "impossible-phase":
				d.OCI.Phase = "auth"
			case "unrelated-content":
				d.OCI.Blob = "verified"
			case "unknown-accepted":
				sub.Disposition = "unknown"
				sub.References = []delivery.Reference{}
			case "invented-already-present":
				o.Code = "already_present"
				o.HTTPStatus = 200
				d.OCI = Facts{Phase: "readback", Manifest: "verified", Blob: "verified"}
			case "bad-capabilities":
				s.Intent.Destination.Capabilities = []string{"submit", "observe-activity"}
			case "bad-expectations":
				s.Intent.ExpectedReferences[0].Value += "bad"
			}
			o.Details = mustJSON(d)
			s.Events[1].Data = mustJSON(sub)
			s.Observations = sub.Observations
			s.Disposition = sub.Disposition
			s.References = sub.References
			if e := ValidateSnapshot(s); e == nil {
				t.Fatal("contradictory OCI evidence accepted", mode)
			}
		})
	}
}
