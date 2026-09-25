package oci

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/rebaze/rio/internal/delivery"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

type client struct {
	options   Options
	repo      *remote.Repository
	auth      *auth.Client
	transport *http.Transport
}
type traversalKey struct{}
type traversalState struct {
	mu              sync.Mutex
	write           bool
	realms          map[string]bool
	status          int
	manifestReceipt *receiptFacts
	rejected        bool
}

func validSecret(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func (p Provider) Build(d delivery.Description, lookup func(string) (string, bool)) (delivery.Target, error) {
	o, _, e := ValidateDescription(d)
	if e != nil {
		return nil, e
	}
	if o.Publication == nil {
		return nil, invalid("prepared publication required")
	}
	ref, e := registry.ParseReference(o.Registry + "/" + o.Repository)
	if e != nil || ref.Registry != o.Registry || ref.Repository != o.Repository || ref.Reference != "" {
		return nil, invalid("registry reference")
	}
	cred := auth.EmptyCredential
	read := func(name string) (string, error) {
		if lookup == nil {
			return "", delivery.Fail("invalid_credentials", "credential resolver required")
		}
		v, ok := lookup(name)
		if !ok || !validSecret(v) {
			return "", delivery.Fail("invalid_credentials", "nonempty header-safe credential required")
		}
		return v, nil
	}
	if o.Auth.UsernameEnv != "" {
		cred.Username, e = read(o.Auth.UsernameEnv)
		if e != nil {
			return nil, e
		}
		if strings.Contains(cred.Username, ":") {
			return nil, delivery.Fail("invalid_credentials", "Basic username cannot contain colon")
		}
		cred.Password, e = read(o.Auth.PasswordEnv)
		if e != nil {
			return nil, e
		}
	}
	if o.Auth.BearerTokenEnv != "" {
		cred.AccessToken, e = read(o.Auth.BearerTokenEnv)
		if e != nil {
			return nil, e
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.CAFile != "" {
		raw, e := delivery.ReadBounded(o.CAFile, delivery.ConfigLimit)
		if e != nil {
			return nil, delivery.Fail("invalid_ca", "cannot read selected CA file")
		}
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(raw) {
			return nil, delivery.Fail("invalid_ca", "CA certificate required")
		}
		tlsConfig.RootCAs = roots
	}
	// Fresh connections avoid net/http's implicit replay on reused connections.
	// HTTP/2 is disabled because it has independent stream retry behavior.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsConfig
	tr.DisableKeepAlives = true
	tr.ForceAttemptHTTP2 = false
	tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	tr.MaxResponseHeaderBytes = ErrorLimit
	tr.ResponseHeaderTimeout = 30 * time.Second
	c := &client{options: o, transport: tr}
	c.auth = &auth.Client{Client: &http.Client{Transport: &safeTransport{base: tr, options: o}, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, Cache: auth.NewCache(), Credential: func(_ context.Context, host string) (auth.Credential, error) {
		if host != o.Registry {
			return auth.EmptyCredential, delivery.Fail("auth_origin_refused", "credential target")
		}
		return cred, nil
	}}
	c.auth.SetUserAgent("rio-oci")
	c.repo, e = remote.NewRepository(o.Registry + "/" + o.Repository)
	if e != nil {
		return nil, invalid("repository")
	}
	c.repo.Client = registryClient{c}
	c.repo.PlainHTTP = o.AllowHTTP
	c.repo.MaxMetadataBytes = DocumentLimit
	// Force required API mode, including standalone pushes, so the SDK cannot
	// enter any automatic referrers-tag maintenance path.
	if e = c.repo.SetReferrersCapability(true); e != nil {
		return nil, invalid("referrers policy")
	}
	return c, nil
}
func (c *client) traversal(parent context.Context, write bool) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	ctx = context.WithValue(ctx, traversalKey{}, &traversalState{write: write, realms: map[string]bool{}})
	actions := []string{auth.ActionPull}
	if write {
		actions = append(actions, auth.ActionPush)
	}
	ctx = auth.AppendRepositoryScope(ctx, c.repo.Reference, actions...)
	return ctx, cancel
}
func (c *client) request(ctx context.Context, method, path string, body func() (io.ReadCloser, error), size int64, mediaType string) (*http.Response, error) {
	raw := path
	if strings.HasPrefix(path, "/") {
		raw = origin(c.options) + path
	}
	req, e := http.NewRequestWithContext(ctx, method, raw, nil)
	if e != nil {
		return nil, delivery.Fail("invalid_request", "OCI request")
	}
	if body != nil {
		req.Body, e = body()
		if e != nil {
			return nil, delivery.Fail("payload_unavailable", "verified snapshot")
		}
		req.GetBody = body
		req.ContentLength = size
	}
	if mediaType != "" {
		req.Header.Set("Content-Type", mediaType)
	}
	req.Header.Set("Accept", ManifestMediaType+", "+IndexMediaType+", "+DockerManifestMediaType+", "+DockerIndexMediaType)
	resp, e := c.do(req)
	if e != nil {
		return nil, safeError(e)
	}
	return resp, nil
}
func safeError(e error) error {
	var safe *delivery.Error
	if errors.As(e, &safe) {
		return safe
	}
	return delivery.Fail("transport_unavailable", "OCI request unavailable")
}
func status(ctx context.Context) int {
	if state, ok := ctx.Value(traversalKey{}).(*traversalState); ok {
		state.mu.Lock()
		defer state.mu.Unlock()
		return state.status
	}
	return 0
}

type safeTransport struct {
	base    http.RoundTripper
	options Options
}

func originURL(u *url.URL) string {
	host, e := canonicalRegistry(u.Host, u.Scheme == "http")
	if e != nil {
		return ""
	}
	return u.Scheme + "://" + host
}
func safeURL(u *url.URL) bool {
	if u.User != nil || u.Fragment != "" || u.Opaque != "" || u.Host == "" || strings.ContainsAny(u.Path, "\\%") || strings.ContainsAny(u.RawQuery, "\r\n") {
		return false
	}
	escaped := strings.ToLower(u.EscapedPath())
	if strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") {
		return false
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}
func (t *safeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	state, ok := req.Context().Value(traversalKey{}).(*traversalState)
	if !ok {
		return nil, delivery.Fail("invalid_request", "bounded OCI traversal required")
	}
	if !safeURL(req.URL) {
		return nil, delivery.Fail("unsafe_location", "OCI request location")
	}
	state.mu.Lock()
	token := state.realms[originURL(req.URL)+req.URL.Path]
	write := state.write
	state.mu.Unlock()
	if token {
		if req.Method != "GET" || !validScopes(req.URL.Query()["scope"], t.options.Repository, write) {
			return nil, delivery.Fail("auth_scope_refused", "token service scope")
		}
	} else {
		if originURL(req.URL) != origin(t.options) || !(req.URL.Path == "/v2/" || strings.HasPrefix(req.URL.Path, "/v2/"+t.options.Repository+"/")) {
			return nil, delivery.Fail("unsafe_location", "request outside selected repository")
		}
		if !write && req.Method != "GET" && req.Method != "HEAD" {
			return nil, delivery.Fail("invalid_request", "read-only traversal")
		}
	}
	ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
	clone := req.Clone(ctx)
	state.mu.Lock()
	state.status = 0
	state.rejected = false
	state.mu.Unlock()
	resp, e := t.base.RoundTrip(clone)
	if e != nil {
		cancel()
		return nil, delivery.Fail("transport_unavailable", "OCI request unavailable")
	}
	state.mu.Lock()
	state.status = resp.StatusCode
	if req.Method == "PUT" && req.URL.Path == "/v2/"+t.options.Repository+"/manifests/"+t.options.Publication.Tag {
		_, locationErr := validLocation(resp.Header.Get("Location"), req.URL, t.options, "manifest")
		state.manifestReceipt = &receiptFacts{Status: resp.StatusCode, Digest: resp.Header.Get("Docker-Content-Digest") == t.options.Publication.Manifest.Digest, Location: locationErr == nil, Subject: t.options.Subject == nil || resp.Header.Get("OCI-Subject") == t.options.Subject.Digest}
	}
	state.mu.Unlock()
	refuse := func(code string) (*http.Response, error) {
		resp.Body.Close()
		cancel()
		return nil, delivery.Fail(code, "OCI response refused")
	}
	limit := DocumentLimit
	if strings.Contains(req.URL.Path, "/blobs/") && (req.Method == "GET" || req.Method == "HEAD") {
		limit = delivery.PayloadLimit
	}
	if token || resp.StatusCode >= 400 {
		limit = ErrorLimit
	}
	if resp.ContentLength > limit {
		return refuse("response_too_large")
	}
	resp.Body = &boundedBody{ReadCloser: resp.Body, remaining: limit, cancel: cancel}
	if !token && resp.StatusCode >= 400 {
		raw, readErr := readResponse(resp, ErrorLimit)
		if readErr != nil {
			return refuse("invalid_error_response")
		}
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
		rejected := supportedRejection(resp)
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		state.mu.Lock()
		state.rejected = rejected
		state.mu.Unlock()
	}
	if resp.StatusCode == 401 && !token {
		scheme, params, e := challenge(resp.Header.Get("Www-Authenticate"))
		if e != nil {
			return refuse("invalid_auth_challenge")
		}
		if scheme == "bearer" {
			realm, e := url.Parse(params["realm"])
			if e != nil || !safeURL(realm) || realm.RawQuery != "" && strings.Contains(realm.RawQuery, "scope=") {
				return refuse("auth_origin_refused")
			}
			trusted := originURL(realm) == origin(t.options)
			for _, v := range t.options.TokenServiceOrigins {
				trusted = trusted || originURL(realm) == v
			}
			if !trusted || realm.Scheme == "http" && originURL(realm) != origin(t.options) || realm.Scheme != "https" && realm.Scheme != "http" {
				return refuse("auth_origin_refused")
			}
			if scope := params["scope"]; scope != "" && !validScopes(strings.Fields(scope), t.options.Repository, write) {
				return refuse("auth_scope_refused")
			}
			state.mu.Lock()
			state.realms[originURL(realm)+realm.Path] = true
			state.mu.Unlock()
		}
	}

	if token && resp.StatusCode == 200 {
		if !jsonMedia(resp.Header.Get("Content-Type")) {
			return refuse("invalid_auth_response")
		}
		raw, e := readResponse(resp, ErrorLimit)
		if e != nil {
			return refuse("invalid_auth_response")
		}
		var m map[string]json.RawMessage
		if delivery.PreflightJSON(raw, &m) != nil || delivery.DecodeJSON(raw, &m, false) != nil {
			return refuse("invalid_auth_response")
		}
		for key := range m {
			if (strings.EqualFold(key, "token") && key != "token") || (strings.EqualFold(key, "access_token") && key != "access_token") {
				return refuse("invalid_auth_response")
			}
		}
		var tokenValue, access string
		for key, dst := range map[string]*string{"token": &tokenValue, "access_token": &access} {
			if value, ok := m[key]; ok {
				if json.Unmarshal(value, dst) != nil || !validSecret(*dst) {
					return refuse("invalid_auth_response")
				}
			}
		}
		if tokenValue == "" && access == "" || tokenValue != "" && access != "" && tokenValue != access {
			return refuse("invalid_auth_response")
		}
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
	}
	return resp, nil
}
func validScopes(scopes []string, repo string, write bool) bool {
	for _, scope := range scopes {
		parts := strings.Split(scope, ":")
		if len(parts) != 3 || parts[0] != "repository" || parts[1] != repo {
			return false
		}
		seen := map[string]bool{}
		for _, action := range strings.Split(parts[2], ",") {
			if seen[action] || action != "pull" && !(write && action == "push") {
				return false
			}
			seen[action] = true
		}
	}
	return true
}

// challenge parses the bounded RFC auth-param grammar without accepting aliases,
// duplicate parameters or unquoted control characters.
func challenge(raw string) (string, map[string]string, error) {
	fields := strings.SplitN(raw, " ", 2)
	scheme := strings.ToLower(fields[0])
	params := map[string]string{}
	if scheme != "basic" && scheme != "bearer" {
		return scheme, params, nil
	}
	if len(fields) != 2 {
		return "", nil, invalid("auth challenge")
	}
	rest := strings.TrimSpace(fields[1])
	for rest != "" {
		eq := strings.IndexByte(rest, '=')
		if eq <= 0 {
			return "", nil, invalid("auth challenge")
		}
		key := strings.TrimSpace(rest[:eq])
		if key != "realm" && key != "service" && key != "scope" && key != "error" {
			return "", nil, invalid("auth challenge")
		}
		if _, exists := params[key]; exists {
			return "", nil, invalid("auth challenge")
		}
		rest = strings.TrimSpace(rest[eq+1:])
		if !strings.HasPrefix(rest, `"`) {
			return "", nil, invalid("auth challenge")
		}
		end := 1
		var value strings.Builder
		for end < len(rest) && rest[end] != '"' {
			ch := rest[end]
			if ch == '\\' {
				end++
				if end >= len(rest) {
					return "", nil, invalid("auth challenge")
				}
				ch = rest[end]
			}
			if ch < 32 || ch == 127 {
				return "", nil, invalid("auth challenge")
			}
			value.WriteByte(ch)
			end++
		}
		if end >= len(rest) {
			return "", nil, invalid("auth challenge")
		}
		params[key] = value.String()
		rest = strings.TrimSpace(rest[end+1:])
		if rest != "" {
			if rest[0] != ',' {
				return "", nil, invalid("auth challenge")
			}
			rest = strings.TrimSpace(rest[1:])
			if rest == "" {
				return "", nil, invalid("auth challenge")
			}
		}
	}
	return scheme, params, nil
}

type boundedBody struct {
	io.ReadCloser
	remaining int64
	cancel    context.CancelFunc
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		var probe [1]byte
		n, e := b.ReadCloser.Read(probe[:])
		if n > 0 {
			return 0, delivery.Fail("response_too_large", "OCI response limit")
		}
		return 0, e
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, e := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, e
}
func (b *boundedBody) Close() error { e := b.ReadCloser.Close(); b.cancel(); return e }
func readResponse(resp *http.Response, limit int64) ([]byte, error) {
	if resp.ContentLength > limit {
		return nil, delivery.Fail("response_too_large", "OCI response limit")
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if e != nil {
		return nil, safeError(e)
	}
	if int64(len(b)) > limit {
		return nil, delivery.Fail("response_too_large", "OCI response limit")
	}
	return b, nil
}
func jsonMedia(value string) bool {
	media, _, e := mime.ParseMediaType(value)
	return e == nil && (media == "application/json" || strings.HasSuffix(media, "+json"))
}
