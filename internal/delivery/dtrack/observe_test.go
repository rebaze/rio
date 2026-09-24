package dtrack

import (
	"context"
	"github.com/rebaze/rio/internal/delivery"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestObserve(t *testing.T) {
	for _, tc := range []struct {
		body   string
		status int
		value  string
	}{{`{"processing":true}`, 200, "processing"}, {`{"processing":false}`, 200, "not-observed"}, {`{}`, 200, "unavailable"}, {`{"processing":null}`, 200, "unavailable"}, {`{"processing":"false"}`, 200, "unavailable"}, {`{"processing":false}`, 401, "unavailable"}, {`{}`, 404, "unavailable"}, {`{}`, 500, "unavailable"}} {
		t.Run(tc.body+http.StatusText(tc.status), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/prefix/api/v1/event/token/"+token {
					t.Error("wrong request")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer s.Close()
			target := targetFor(t, s, "project: {name: app, version: '1'}", false).(delivery.Observer)
			o, _ := target.Observe(context.Background(), []delivery.Reference{{Kind: "dependency-track:event-token", Value: token}})
			if o.Value != tc.value {
				t.Fatal(o)
			}
		})
	}
}

func TestObserveInvalidReferenceSendsNothing(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer s.Close()
	target := targetFor(t, s, "project: {name: app, version: '1'}", false).(delivery.Observer)
	for _, refs := range [][]delivery.Reference{nil, {{Kind: "dependency-track:event-token", Value: "invalid"}}, {{Kind: "dependency-track:event-token", Value: token}, {Kind: "dependency-track:event-token", Value: token}}} {
		if _, e := target.Observe(context.Background(), refs); e == nil {
			t.Fatal("invalid reference accepted")
		}
	}
	if calls != 0 {
		t.Fatal("request with invalid reference")
	}
}

func TestObserveCaseVariantCannotOverrideProcessing(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"processing":true,"Processing":false}`)
	}))
	defer s.Close()
	o, e := targetFor(t, s, "project: {name: app, version: '1'}", false).(delivery.Observer).Observe(context.Background(), []delivery.Reference{{Kind: "dependency-track:event-token", Value: token}})
	if e != nil || o.Value != "processing" {
		t.Fatal("case variant overrode processing", o, e)
	}
}

func TestPersistedActivityRequiresSupportedEvidence(t *testing.T) {
	for _, o := range []delivery.Observation{
		{Kind: "activity", Value: "processing", Origin: "receiver", Code: "activity_observed", HTTPStatus: 403, References: []delivery.Reference{}},
		{Kind: "activity", Value: "not-observed", Origin: "receiver", Code: "invented", HTTPStatus: 200, References: []delivery.Reference{}},
	} {
		if e := ValidateEvidence(nil, []delivery.Observation{o}); e == nil {
			t.Fatal("invented activity evidence accepted")
		}
	}
}
