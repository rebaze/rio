package delivery

import (
	"context"
	"testing"
)

type objectTarget struct{}

func (objectTarget) Submit(context.Context, []Payload) (Submission, error) {
	return Submission{Disposition: "accepted", References: []Reference{{Kind: "object-version", Value: "v1"}}, Observations: []Observation{{Kind: "acknowledgment", Value: "accepted", Origin: "receiver", Code: "stored", References: []Reference{}}}}, nil
}
func TestStorageAcknowledgmentNeedsNoProcessingToken(t *testing.T) {
	ip, _ := verifiedFixture(t)
	v, e := Verify(ip, "application", false)
	if e != nil {
		t.Fatal(e)
	}
	var target Target = objectTarget{}
	s, e := target.Submit(context.Background(), v.Payloads())
	if e != nil || s.References[0].Kind != "object-version" || s.Observations[0].Kind != "acknowledgment" {
		t.Fatal(s, e)
	}
}
