package dtrack

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/rebaze/rio/internal/delivery"
	"io"
	"mime"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
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
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, InsecureSkipVerify: o.InsecureSkipVerify} // Explicit, persisted HTTPS-only policy.
	transport.DisableKeepAlives = true
	return &client{http: &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, options: o, identity: id, key: key}, nil
}
func (c *client) request(ctx context.Context, method, path, ct string, body io.Reader) (*http.Response, bool, error) {
	req, e := http.NewRequestWithContext(ctx, method, c.identity.URL+path, body)
	if e != nil {
		return nil, false, delivery.Fail("request_invalid", "request construction")
	}
	req.Header.Set("X-Api-Key", c.key)
	req.Header.Set("Accept", "application/json")
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	var observed atomic.Bool
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		// GotConn is emitted after CONNECT and the origin TLS handshake. A
		// TLSHandshakeDone callback alone may describe only an HTTPS proxy.
		// Retain this fact even when the subsequent HTTP response is lost.
		GotConn: func(info httptrace.GotConnInfo) {
			if req.URL.Scheme == "https" {
				if conn, ok := info.Conn.(*tls.Conn); ok && conn.ConnectionState().HandshakeComplete {
					observed.Store(true)
				}
			}
		},
	}))
	// body has no GetBody and no idempotency key; no redirect or upload replay.
	resp, e := c.http.Do(req)
	if e != nil {
		return nil, observed.Load(), delivery.Fail("transport_unavailable", "request outcome unavailable")
	}
	return resp, observed.Load(), nil
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
		if _, e := ReadTLS(o); e != nil {
			return e
		}
		if o.Kind == "activity" && (o.Origin != "receiver" || o.HTTPStatus != 200 || o.Code != "activity_observed" || (o.Value != "processing" && o.Value != "not-observed") || len(o.References) != 0) {
			return delivery.Fail("invalid_record", "Dependency-Track activity")
		}
		if o.Kind == "unavailable" {
			valid := false
			switch o.Code {
			case "transport_unavailable", "missing_reference":
				valid = o.Origin == "local" && o.HTTPStatus == 0
			case "query_transient":
				valid = o.Origin == "receiver" && (o.HTTPStatus == 429 || o.HTTPStatus >= 500)
			case "query_rejected":
				valid = o.Origin == "receiver" && o.HTTPStatus != 200 && o.HTTPStatus != 429 && o.HTTPStatus < 500
			case "invalid_response":
				valid = o.Origin == "receiver" && o.HTTPStatus == 200
			}
			if !valid || o.Value != "unavailable" || len(o.References) != 0 {
				return delivery.Fail("invalid_record", "Dependency-Track unavailable observation")
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

// ValidateSubmission binds saved disposition to the evidence this adapter can produce.
func ValidateSubmission(sub delivery.Submission) error {
	bad := func() error { return delivery.Fail("invalid_record", "inconsistent Dependency-Track submission") }
	if err := ValidateEvidence(sub.References, sub.Observations); err != nil {
		return err
	}
	if len(sub.Observations) != 1 {
		return bad()
	}
	o := sub.Observations[0]
	switch sub.Disposition {
	case "accepted":
		if len(sub.References) != 1 || o.Kind != "acknowledgment" || o.Value != "accepted" || o.Origin != "receiver" || o.Code != "accepted" || o.HTTPStatus != 200 || len(o.References) != 1 || o.References[0] != sub.References[0] {
			return bad()
		}
	case "rejected":
		if len(sub.References) != 0 || o.Kind != "acknowledgment" || o.Value != "rejected" || o.Origin != "receiver" || o.Code != "upload_rejected" || len(o.References) != 0 {
			return bad()
		}
		switch o.HTTPStatus {
		case 400, 401, 403, 404, 413, 415, 422:
		default:
			return bad()
		}
	case "unknown":
		if len(sub.References) != 0 || len(o.References) != 0 {
			return bad()
		}
		if o.Kind == "unavailable" {
			if o.Code != "transport_unavailable" || o.Origin != "local" || o.HTTPStatus != 0 {
				return bad()
			}
		} else {
			if o.Kind != "acknowledgment" || o.Value != "unknown" || o.Origin != "receiver" {
				return bad()
			}
			if o.Code == "invalid_receipt" {
				if o.HTTPStatus != 200 {
					return bad()
				}
			} else if o.Code != "unexpected_status" {
				return bad()
			}
		}
	default:
		return bad()
	}
	return nil
}
