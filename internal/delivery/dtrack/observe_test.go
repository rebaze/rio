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
