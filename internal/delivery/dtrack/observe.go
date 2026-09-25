package dtrack

import (
	"context"
	"github.com/rebaze/rio/internal/delivery"
)

func EventToken(refs []delivery.Reference) (string, error) {
	token := ""
	for _, r := range refs {
		if r.Kind == "dependency-track:event-token" {
			if token != "" || !ValidUUID(r.Value) {
				return "", delivery.Fail("invalid_reference", "event token")
			}
			token = r.Value
		}
	}
	if token == "" {
		return "", delivery.Fail("missing_reference", "no saved event token; cannot reconcile")
	}
	return token, nil
}
func (c *client) Observe(ctx context.Context, refs []delivery.Reference) (o delivery.Observation, err error) {
	o = observation("unavailable", "unavailable", "local", "missing_reference", 0)
	var tlsObserved bool
	defer func() { c.addTLS(&o, tlsObserved) }()
	token, e := EventToken(refs)
	if e != nil {
		return o, e
	}
	resp, observed, e := c.request(ctx, "GET", "/api/v1/event/token/"+token, "", nil)
	tlsObserved = observed
	if e != nil {
		o.Code = "transport_unavailable"
		return o, e
	}
	defer resp.Body.Close()
	o.Origin = "receiver"
	o.HTTPStatus = resp.StatusCode
	o.Code = "query_rejected"
	if resp.StatusCode != 200 {
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			o.Code = "query_transient"
		}
		return o, delivery.Fail(o.Code, "activity unavailable")
	}
	var result struct {
		Processing bool `json:"processing"`
	}
	if e = responseJSON(resp, &result); e != nil {
		o.Code = "invalid_response"
		return o, e
	}
	o.Kind = "activity"
	o.Value = "not-observed"
	o.Code = "activity_observed"
	if result.Processing {
		o.Value = "processing"
	}
	return o, nil
}
