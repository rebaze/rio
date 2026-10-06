package dtrack

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubmissionRecordsOnlyObservedCompleteBodyWrites(t *testing.T) {
	v := payload(t)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		c, _, e := w.(http.Hijacker).Hijack()
		if e == nil {
			c.Close()
		}
	}))
	defer s.Close()
	c := targetFor(t, s, "project: {fromSubject: true}", false)
	sub, e := c.Submit(context.Background(), v.Payloads())
	if e == nil || sub.Disposition != "unknown" || len(sub.Submitted) != 1 || sub.Submitted[0] != v.Payloads()[0].Ref() {
		t.Fatalf("lost-response write facts: %#v %v", sub, e)
	}
	s.Close()
	sub, e = c.Submit(context.Background(), v.Payloads())
	if e == nil || len(sub.Submitted) != 0 {
		t.Fatalf("unconnected target claimed written body: %#v %v", sub, e)
	}
}
