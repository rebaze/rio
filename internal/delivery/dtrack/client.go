package dtrack

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

const responseLimit int64 = 64 << 10

type client struct {
	http     *http.Client
	options  Options
	identity Identity
	key      string
}

func (Provider) Build(d delivery.Description, lookup func(string) (string, bool)) (delivery.Target, error) {
	o, id, e := ValidateDescription(d)
	if e != nil {
		return nil, e
	}
	key, ok := lookup(o.APIKeyEnv)
	if !ok || key == "" || strings.ContainsAny(key, "\r\n") {
		return nil, delivery.Fail("invalid_credential", "selected environment variable missing or invalid")
	}
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if o.CAFile != "" {
		b, e := delivery.ReadBounded(o.CAFile, delivery.ConfigLimit)
		if e != nil || !roots.AppendCertsFromPEM(b) {
			return nil, delivery.Fail("invalid_ca", "selected caFile")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	transport.DisableKeepAlives = true
	return &client{http: &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, options: o, identity: id, key: key}, nil
}
func (c *client) request(ctx context.Context, method, path, ct string, body io.Reader) (*http.Response, error) {
	req, e := http.NewRequestWithContext(ctx, method, c.identity.URL+path, body)
	if e != nil {
		return nil, delivery.Fail("request_invalid", "request construction")
	}
	req.Header.Set("X-Api-Key", c.key)
	req.Header.Set("Accept", "application/json")
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	// body has no GetBody and no idempotency key; no redirect or upload replay.
	resp, e := c.http.Do(req)
	if e != nil {
		return nil, delivery.Fail("transport_unavailable", "request outcome unavailable")
	}
	return resp, nil
}
func responseJSON(resp *http.Response, out any) error {
	typ, _, e := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if e != nil || (typ != "application/json" && !(strings.HasPrefix(typ, "application/") && strings.HasSuffix(typ, "+json"))) {
		return delivery.Fail("invalid_response", "JSON content type required")
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
	if e != nil || int64(len(b)) > responseLimit {
		return delivery.Fail("invalid_response", "response size or read failure")
	}
	if delivery.DecodeJSON(b, out, false) != nil {
		return delivery.Fail("invalid_response", "response schema")
	}
	return nil
}
func observation(kind, value, origin, code string, status int) delivery.Observation {
	return delivery.Observation{Kind: kind, Value: value, Origin: origin, Code: code, HTTPStatus: status, References: []delivery.Reference{}}
}

// ValidateEvidence prevents persisted adapter data from gaining new meanings.
func ValidateEvidence(refs []delivery.Reference, observations []delivery.Observation) error {
	for _, r := range refs {
		if r.Kind != "dependency-track:event-token" || !ValidUUID(r.Value) {
			return delivery.Fail("invalid_record", "Dependency-Track reference")
		}
	}
	for _, o := range observations {
		if o.Details != nil {
			var m map[string]json.RawMessage
			if delivery.DecodeJSON(o.Details, &m, true) != nil || len(m) != 0 {
				return delivery.Fail("invalid_record", "Dependency-Track details")
			}
		}
		if o.Kind == "content" {
			return delivery.Fail("invalid_record", "unsupported content observation")
		}
		if e := ValidateEvidence(o.References, nil); e != nil {
			return e
		}
	}
	return nil
}
