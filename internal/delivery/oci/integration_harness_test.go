package oci

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/delivery/runner"
	"github.com/rebaze/rio/internal/evidence"
	"github.com/rebaze/rio/internal/index"
	"gopkg.in/yaml.v3"
)

type integrationConfig struct {
	registry, repository, auth, ca, product, version, image, evidencePath, referrers string
	plain, immutable, deniedCanRead                                                  bool
	canaries                                                                         []string
}

func integrationSettings(get func(string) string) (integrationConfig, error) {
	c := integrationConfig{registry: get("RIO_OCI_TEST_REGISTRY"), repository: get("RIO_OCI_TEST_REPOSITORY"), auth: get("RIO_OCI_TEST_AUTH"), ca: get("RIO_OCI_TEST_CA_FILE"), product: get("RIO_OCI_TEST_PRODUCT"), version: get("RIO_OCI_TEST_VERSION"), image: get("RIO_OCI_TEST_IMAGE_DIGEST"), evidencePath: get("RIO_OCI_TEST_EVIDENCE"), referrers: get("RIO_OCI_TEST_REFERRERS"), plain: get("RIO_OCI_TEST_ALLOW_HTTP") == "1", immutable: get("RIO_OCI_TEST_IMMUTABLE") == "1", deniedCanRead: get("RIO_OCI_TEST_DENIED_CAN_READ") == "1"}
	if c.registry == "" || c.repository == "" {
		return c, invalid("integration registry and repository required")
	}
	if c.referrers == "" {
		c.referrers = "required"
	}
	if c.referrers != "required" && c.referrers != "unsupported" {
		return c, invalid("explicit integration Referrers expectation")
	}
	if c.auth == "" {
		c.auth = "basic"
	}
	if c.auth != "basic" && c.auth != "anonymous" {
		return c, invalid("explicit integration auth mode")
	}
	for _, key := range []string{"RIO_OCI_TEST_ALLOW_HTTP", "RIO_OCI_TEST_IMMUTABLE", "RIO_OCI_TEST_DENIED_CAN_READ"} {
		v := get(key)
		if v != "" && v != "0" && v != "1" {
			return c, invalid("integration boolean environment")
		}
	}
	if c.auth == "basic" {
		for _, key := range []string{"RIO_OCI_TEST_USERNAME", "RIO_OCI_TEST_PASSWORD", "RIO_OCI_TEST_DENIED_USERNAME", "RIO_OCI_TEST_DENIED_PASSWORD"} {
			v := get(key)
			if !validSecret(v) {
				return c, invalid("required integration credential environment")
			}
			c.canaries = append(c.canaries, v)
		}
	}
	return c, nil
}

type integrationRequest struct {
	Operation            string `json:"operation"`
	Method               string `json:"method"`
	Path                 string `json:"path"`
	Status               int    `json:"status"`
	Digest               string `json:"digest,omitempty"`
	Subject              string `json:"subject,omitempty"`
	LocationPresent      *bool  `json:"manifestLocationPresent,omitempty"`
	LocationSameOrigin   *bool  `json:"manifestLocationSameOrigin,omitempty"`
	LocationExpectedPath *bool  `json:"manifestLocationExpectedPath,omitempty"`
	LocationHasQuery     *bool  `json:"manifestLocationHasQuery,omitempty"`
	LocationTemplate     string `json:"manifestLocationTemplate,omitempty"`
}
type integrationScenario struct {
	Name                    string      `json:"name"`
	Acknowledgment          string      `json:"acknowledgment,omitempty"`
	Verification            string      `json:"verification,omitempty"`
	ExitCode                int         `json:"exitCode"`
	Manifest                *Descriptor `json:"manifest,omitempty"`
	Subject                 *Descriptor `json:"subject,omitempty"`
	SBOMSHA256              string      `json:"sbomSHA256,omitempty"`
	ReadbackSHA256          string      `json:"readbackSHA256,omitempty"`
	PublicationBegan        *bool       `json:"publicationBegan,omitempty"`
	HTTPStatus              int         `json:"httpStatus,omitempty"`
	ProxyObservedHTTPStatus int         `json:"proxyObservedUpstreamHTTPStatus,omitempty"`
	Outcome                 string      `json:"outcome"`
}
type integrationEvidence struct {
	SchemaVersion        int                   `json:"schemaVersion"`
	Kind                 string                `json:"kind"`
	RealRegistry         bool                  `json:"realRegistry"`
	SyntheticContent     bool                  `json:"syntheticContent"`
	Complete             bool                  `json:"complete"`
	Product              string                `json:"setupReportedProduct"`
	Version              string                `json:"setupReportedVersion"`
	ImageDigest          string                `json:"setupReportedImageDigest"`
	Registry             string                `json:"registry"`
	Repository           string                `json:"repository"`
	Auth                 string                `json:"auth"`
	TLS                  bool                  `json:"tls"`
	CustomCA             bool                  `json:"customCA"`
	ImmutablePolicy      bool                  `json:"expectedImmutableTagPolicy"`
	DeniedCanRead        bool                  `json:"expectedDeniedAccountCanRead"`
	Scenarios            []integrationScenario `json:"scenarios"`
	Requests             []integrationRequest  `json:"requests"`
	RecordSHA256         string                `json:"recordSHA256,omitempty"`
	RecordBytes          int                   `json:"recordBytes,omitempty"`
	ReferrersExpectation string                `json:"expectedReferrersCapability"`
}
type integrationTrace struct {
	mu       sync.Mutex
	requests []integrationRequest
}

func (x *integrationTrace) copy() []integrationRequest {
	x.mu.Lock()
	defer x.mu.Unlock()
	return append([]integrationRequest{}, x.requests...)
}
func (x *integrationTrace) writes() int {
	x.mu.Lock()
	defer x.mu.Unlock()
	n := 0
	for _, r := range x.requests {
		if r.Method != "GET" && r.Method != "HEAD" {
			n++
		}
	}
	return n
}

type integrationTransport struct {
	base                  http.RoundTripper
	trace                 *integrationTrace
	operation, repository string
}

func (tr *integrationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, e := tr.base.RoundTrip(req)
	fact := integrationRequest{Operation: tr.operation, Method: req.Method, Path: req.URL.Path}
	prefix := "/v2/" + tr.repository + "/"
	if strings.Contains(fact.Path, "/blobs/uploads/") {
		fact.Path = prefix + "blobs/uploads/<session>"
	} else if fact.Path != "/v2/" && !strings.HasPrefix(fact.Path, prefix) {
		fact.Path = "<token-service>"
	}
	if resp != nil {
		fact.Status = resp.StatusCode
		for key, dst := range map[string]*string{"Docker-Content-Digest": &fact.Digest, "OCI-Subject": &fact.Subject} {
			v := resp.Header.Get(key)
			if strings.HasPrefix(v, "sha256:") && delivery.ValidDigest(strings.TrimPrefix(v, "sha256:")) {
				*dst = v
			}
		}
	}
	if resp != nil && req.Method == "PUT" && strings.Contains(req.URL.Path, "/manifests/") {
		raw := resp.Header.Get("Location")
		present := raw != ""
		same, path, query := false, false, false
		if relative, err := url.Parse(raw); err == nil && present {
			location := req.URL.ResolveReference(relative)
			same = originURL(location) == originURL(req.URL)
			path = location.Path == req.URL.Path || fact.Digest != "" && location.Path == "/v2/"+tr.repository+"/manifests/"+fact.Digest
			query = location.RawQuery != ""
			parts := strings.Split(location.Path, "/")
			for i, part := range parts {
				if strings.HasPrefix(part, "sha256:") && delivery.ValidDigest(strings.TrimPrefix(part, "sha256:")) {
					parts[i] = "<digest>"
				} else if delivery.ValidDigest(part) {
					parts[i] = "<hex-digest>"
				} else if strings.HasPrefix(part, "rio-sbom-sha256-") {
					parts[i] = "<generated-tag>"
				} else if part == "" || part == "v2" || part == "repository" || part == "manifests" || strings.Contains("/"+tr.repository+"/", "/"+part+"/") {
				} else {
					parts[i] = "<other>"
				}
			}
			fact.LocationTemplate = strings.Join(parts, "/")
		}
		fact.LocationPresent = &present
		fact.LocationSameOrigin = &same
		fact.LocationExpectedPath = &path
		fact.LocationHasQuery = &query
	}
	tr.trace.mu.Lock()
	tr.trace.requests = append(tr.trace.requests, fact)
	tr.trace.mu.Unlock()
	return resp, e
}

type integrationTarget struct {
	client       *client
	description  delivery.Description
	configSHA256 string
}

func integrationTargetFor(t *testing.T, c integrationConfig, v delivery.Verified, subject *Descriptor, denied bool, trace *integrationTrace, label, dir string) integrationTarget {
	t.Helper()
	a := map[string]any{"anonymous": true}
	if c.auth != "anonymous" {
		u, p := "RIO_OCI_TEST_USERNAME", "RIO_OCI_TEST_PASSWORD"
		if denied {
			u, p = "RIO_OCI_TEST_DENIED_USERNAME", "RIO_OCI_TEST_DENIED_PASSWORD"
		}
		a = map[string]any{"usernameEnv": u, "passwordEnv": p}
	}
	options := map[string]any{"registry": c.registry, "repository": c.repository, "allowHTTP": c.plain, "auth": a}
	if c.ca != "" {
		options["caFile"] = c.ca
	}
	if subject != nil {
		options["subject"] = map[string]any{"mediaType": subject.MediaType, "digest": subject.Digest, "size": subject.Size}
	}
	var dn, bn yaml.Node
	dn.Encode(options)
	bn.Encode(map[string]any{})
	d, e := (Provider{Directory: dir}).Describe(dn, bn, delivery.Subject{})
	if e != nil {
		t.Fatal("integration description refused", safeError(e))
	}
	d.DestinationName = "integration"
	prep, e := (Provider{}).Prepare(d, v.Source(), []delivery.PayloadRef{v.Payloads()[0].Ref()})
	if e != nil {
		t.Fatal("integration preparation refused", safeError(e))
	}
	built, e := (Provider{}).Build(prep.Description, os.LookupEnv)
	if e != nil {
		t.Fatal("integration credentials or transport refused", safeError(e))
	}
	client := built.(*client)
	guard := client.auth.Client.Transport.(*safeTransport)
	guard.base = &integrationTransport{guard.base, trace, label, c.repository}
	targetOptions := map[string]any{}
	for k, value := range options {
		targetOptions[k] = value
	}
	targetOptions["type"] = "oci"
	raw, e := yaml.Marshal(map[string]any{"version": 1, "artifacts": []map[string]any{{"id": "app", "sbom": "bom.json"}}, "delivery": map[string]any{"targets": map[string]any{"integration": targetOptions}}})
	if e != nil {
		t.Fatal("integration manifest encoding failed")
	}
	if e = os.WriteFile(filepath.Join(dir, "rio.yaml"), raw, 0600); e != nil {
		t.Fatal("integration manifest write failed")
	}
	return integrationTarget{client, prep.Description, delivery.Digest(raw)}
}
func integrationSourceName(id string) string {
	if id == "app" {
		return "bom.json"
	}
	return id + ".json"
}
func integrationInput(t *testing.T) (delivery.Verified, string, string) {
	t.Helper()
	dir := t.TempDir()
	entropy := make([]byte, 12)
	if _, e := rand.Read(entropy); e != nil {
		t.Fatal("synthetic identity generation failed")
	}
	nonce := hex.EncodeToString(entropy)
	declarations := []map[string]any{}
	artifacts := []index.Artifact{}
	for _, id := range []string{"app", "conflict", "denied", "crash"} {
		name := integrationSourceName(id)
		raw := []byte(fmt.Sprintf("{\n  \"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"version\":1,\"metadata\":{\"component\":{\"type\":\"application\",\"name\":\"rio-synthetic-integration-%s\",\"version\":\"0.0.0-%s\"}},\"components\":[]\n}\n", id, nonce))
		if e := os.WriteFile(filepath.Join(dir, name), raw, 0600); e != nil {
			t.Fatal("synthetic SBOM write failed")
		}
		hash := delivery.Digest(raw)
		declarations = append(declarations, map[string]any{"id": id, "sbom": name})
		artifacts = append(artifacts, index.Artifact{ID: id, Input: index.FileRef{Path: name, SHA256: hash}, Output: index.FileRef{Path: name, SHA256: hash}, SpecVersion: index.SpecVersions{Input: "1.6", Output: "1.6"}, Gate: index.GateOK})
	}
	manifest, e := yaml.Marshal(map[string]any{"version": 1, "artifacts": declarations})
	if e != nil {
		t.Fatal("synthetic manifest failed")
	}
	os.WriteFile(filepath.Join(dir, "rio.yaml"), manifest, 0600)
	idx := index.New("integration", index.FileRef{Path: "rio.yaml", SHA256: delivery.Digest(manifest)})
	idx.Artifacts = artifacts
	if _, e = index.Write(dir, idx); e != nil {
		t.Fatal("synthetic index write failed")
	}
	ip := filepath.Join(dir, "index.json")
	v, e := delivery.Verify(ip, "app", false)
	if e != nil {
		t.Fatal("synthetic handoff verification failed", safeError(e))
	}
	return v, ip, nonce
}
func integrationReadiness(t *testing.T, c *client) {
	t.Helper()
	ctx, cancel := c.traversal(context.Background(), true)
	defer cancel()
	deadline := time.Now().Add(45 * time.Second)
	for {
		resp, e := c.request(ctx, "GET", "/v2/", nil, 0, "")
		if resp != nil {
			resp.Body.Close()
			if e == nil && resp.StatusCode == 200 {
				return
			}
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				t.Fatal("integration registry rejected setup credentials")
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("integration registry did not become ready")
		}
		time.Sleep(250 * time.Millisecond)
	}
}
func integrationSeedBlob(t *testing.T, c *client, raw []byte, media string) Descriptor {
	t.Helper()
	d := Descriptor{media, "sha256:" + delivery.Digest(raw), int64(len(raw))}
	ctx, cancel := c.traversal(context.Background(), true)
	defer cancel()
	resp, e := c.request(ctx, "POST", "/v2/"+c.options.Repository+"/blobs/uploads/", nil, 0, "")
	if e != nil {
		t.Fatal("fixture blob session unavailable", safeError(e))
	}
	if resp.StatusCode != 202 {
		resp.Body.Close()
		t.Fatalf("fixture blob session status %d", resp.StatusCode)
	}
	loc, e := validLocation(resp.Header.Get("Location"), resp.Request.URL, c.options, "upload")
	resp.Body.Close()
	if e != nil {
		t.Fatal("fixture upload location refused", safeError(e))
	}
	if loc.RawQuery != "" {
		loc.RawQuery += "&"
	}
	loc.RawQuery += "digest=" + url.QueryEscape(d.Digest)
	resp, e = c.request(ctx, "PUT", loc.String(), func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }, d.Size, "application/octet-stream")
	if e != nil {
		t.Fatal("fixture blob upload unavailable", safeError(e))
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("fixture blob completion status %d", resp.StatusCode)
	}
	return d
}
func integrationFetch(t *testing.T, c *client, path string, limit int64) ([]byte, *http.Response) {
	t.Helper()
	ctx, cancel := c.traversal(context.Background(), false)
	defer cancel()
	probe, probeErr := c.request(ctx, "GET", "/v2/", nil, 0, "")
	if probeErr != nil {
		t.Fatal("independent read auth preflight unavailable", safeError(probeErr))
	}
	if probe.StatusCode != 200 {
		probe.Body.Close()
		t.Fatalf("independent read auth status %d", probe.StatusCode)
	}
	probe.Body.Close()
	resp, e := c.request(ctx, "GET", "/v2/"+c.options.Repository+"/"+path, nil, 0, "")
	if e != nil {
		t.Fatal("independent registry retrieval unavailable", safeError(e))
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("independent registry retrieval status %d", resp.StatusCode)
	}
	raw, e := readResponse(resp, limit)
	if e != nil {
		t.Fatal("independent registry retrieval refused", safeError(e))
	}
	return raw, resp
}
func integrationSeedManifest(t *testing.T, c *client, raw []byte, media, tag string) Descriptor {
	t.Helper()
	d := Descriptor{media, "sha256:" + delivery.Digest(raw), int64(len(raw))}
	ctx, cancel := c.traversal(context.Background(), true)
	defer cancel()
	probe, probeErr := c.request(ctx, "GET", "/v2/", nil, 0, "")
	if probeErr != nil {
		t.Fatal("fixture write auth preflight unavailable", safeError(probeErr))
	}
	if probe.StatusCode != 200 {
		probe.Body.Close()
		t.Fatalf("fixture write auth status %d", probe.StatusCode)
	}
	probe.Body.Close()
	if e := c.repo.Manifests().PushReference(ctx, ociDescriptor(d), bytes.NewReader(raw), tag); e != nil {
		t.Fatalf("fixture manifest publication failed (HTTP %d)", status(ctx))
	}
	got, resp := integrationFetch(t, c, "manifests/"+d.Digest, DocumentLimit)
	actualMedia, _, e := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if e != nil || actualMedia != media || !bytes.Equal(got, raw) {
		t.Fatal("fixture descriptor read-back mismatch")
	}
	return Descriptor{actualMedia, "sha256:" + delivery.Digest(got), int64(len(got))}
}
func integrationSeedIndex(t *testing.T, c *client, image Descriptor, nonce, label string) Descriptor {
	t.Helper()
	raw := mustJSON(map[string]any{"schemaVersion": 2, "mediaType": IndexMediaType, "manifests": []any{map[string]any{"mediaType": image.MediaType, "digest": image.Digest, "size": image.Size, "platform": map[string]any{"os": "linux", "architecture": "amd64"}}}, "annotations": map[string]string{"io.rebaze.rio.synthetic-case": label}})
	return integrationSeedManifest(t, c, raw, IndexMediaType, "rio-integration-index-"+nonce+"-"+label)
}
func integrationPrepared(target integrationTarget, v delivery.Verified) runner.Prepared {
	return runner.Prepared{Verified: v, Description: target.description, ExpectedReferences: expected(target.client.options), ValidateIntent: ValidateIntent, Intent: record.Intent{RioVersion: "integration", Binding: "integration", ConfigSHA256: target.configSHA256}, Target: target.client}
}
func integrationSubmit(t *testing.T, target integrationTarget, v delivery.Verified, path string, want int, prior string) runner.Result {
	t.Helper()
	p := integrationPrepared(target, v)
	if prior != "" {
		s, e := record.Read(prior)
		if e != nil {
			t.Fatal("prior integration journal unreadable")
		}
		p.Intent.Retry, e = runner.Retry(s, v, p.Description, SamePolicy(s.Intent.Destination, p.Description, false), prior)
		if e != nil {
			t.Fatal("integration retry refused", safeError(e))
		}
	}
	result, e := runner.Submit(context.Background(), p, path)
	if result.ExitCode != want {
		code := "none"
		if result.Error != nil {
			code = result.Error.Code
		}
		t.Fatalf("integration submit expected exit %d, observed %d (%s)", want, result.ExitCode, code)
	}
	if want == 0 && e != nil {
		t.Fatal("integration submit failed without expected exit")
	}
	s, e := record.Read(path)
	if e != nil || ValidateSnapshot(s) != nil {
		t.Fatal("integration journal not independently valid")
	}
	return result
}
func integrationReconcile(t *testing.T, target integrationTarget, path string) runner.Result {
	t.Helper()
	w, e := record.Open(path)
	if e != nil {
		t.Fatal("integration journal unavailable for reconciliation")
	}
	r, e := runner.Reconcile(context.Background(), w, target.client, target.configSHA256, 0)
	closeErr := w.Close()
	if e != nil || closeErr != nil || r.Verification != "verified" {
		code := "none"
		if r.Error != nil {
			code = r.Error.Code
		}
		t.Fatalf("integration read-back failed (%s, verification %s)", code, r.Verification)
	}
	return r
}
func integrationResult(name string, r runner.Result, target integrationTarget) integrationScenario {
	pub := target.client.options.Publication
	s := integrationScenario{Name: name, Acknowledgment: r.Acknowledgment, Verification: r.Verification, ExitCode: r.ExitCode, Manifest: &pub.Manifest, Subject: pub.Subject, SBOMSHA256: pub.Payload.SHA256, Outcome: r.Outcome}
	for _, o := range r.Observations {
		var d details
		if o.Kind == "acknowledgment" && json.Unmarshal(o.Details, &d) == nil {
			b := d.OCI.PublicationBegan
			s.PublicationBegan = &b
		}
		if o.Kind == "acknowledgment" {
			s.HTTPStatus = o.HTTPStatus
		}
	}
	return s
}

type integrationChild struct {
	Index, Journal, ArtifactID string
	Description                delivery.Description
	ConfigSHA256               string
	ExpectedReferences         []delivery.Reference
}

func integrationChildRun(t *testing.T) {
	t.Helper()
	raw, e := delivery.ReadBounded(os.Getenv("RIO_OCI_TEST_CHILD_INPUT"), record.EventLimit)
	if e != nil {
		t.Fatal("child input unavailable")
	}
	var child integrationChild
	if json.Unmarshal(raw, &child) != nil {
		t.Fatal("child input invalid")
	}
	v, e := delivery.Verify(child.Index, child.ArtifactID, false)
	if e != nil {
		t.Fatal("child verification failed", safeError(e))
	}
	target, e := (Provider{}).Build(child.Description, os.LookupEnv)
	if e != nil {
		t.Fatal("child transport preflight failed", safeError(e))
	}
	_, e = runner.Submit(context.Background(), runner.Prepared{Verified: v, Description: child.Description, ExpectedReferences: child.ExpectedReferences, ValidateIntent: ValidateIntent, Intent: record.Intent{RioVersion: "integration", Binding: "integration", ConfigSHA256: child.ConfigSHA256}, Target: target}, child.Journal)
	if e != nil {
		t.Fatal("child submission failed", safeError(e))
	}
	t.Fatal("child unexpectedly completed before controlled crash")
}
func integrationCrashProxy(t *testing.T, base integrationConfig, upstream *client, trace *integrationTrace) (integrationConfig, *httptest.Server, *atomic.Bool, chan struct{}, chan struct{}) {
	t.Helper()
	originURLParsed, _ := url.Parse(origin(upstream.options))
	stored, release := make(chan struct{}, 1), make(chan struct{})
	armed := &atomic.Bool{}
	var proxyServer *httptest.Server
	reverse := httputil.NewSingleHostReverseProxy(originURLParsed)
	transport := upstream.transport.Clone()
	transport.DisableKeepAlives = true
	reverse.Transport = &integrationTransport{transport, trace, "crash-proxy-upstream", base.repository}
	dropped := errors.New("controlled synthetic response loss")
	reverse.ModifyResponse = func(resp *http.Response) error {
		proxyURL, _ := url.Parse(proxyServer.URL)
		if raw := resp.Header.Get("Location"); raw != "" {
			relative, e := url.Parse(raw)
			if e == nil {
				u := resp.Request.URL.ResolveReference(relative)
				if originURL(u) == origin(upstream.options) || u.Host == proxyURL.Host {
					u.Scheme = proxyURL.Scheme
					u.Host = proxyURL.Host
					resp.Header.Set("Location", u.String())
				}
			}
		}
		scheme, params, e := challenge(resp.Header.Get("Www-Authenticate"))
		if e == nil && scheme == "bearer" {
			realm, e := url.Parse(params["realm"])
			if e == nil && (originURL(realm) == origin(upstream.options) || realm.Host == proxyURL.Host) {
				realm.Scheme = proxyURL.Scheme
				realm.Host = proxyURL.Host
				params["realm"] = realm.String()
				parts := []string{}
				for _, key := range []string{"realm", "service", "scope", "error"} {
					if value, ok := params[key]; ok {
						parts = append(parts, key+"="+strconv.Quote(value))
					}
				}
				resp.Header.Set("Www-Authenticate", "Bearer "+strings.Join(parts, ","))
			}
		}
		if resp.Request.Method == "PUT" && strings.Contains(resp.Request.URL.Path, "/manifests/rio-sbom-sha256-") && resp.StatusCode == 201 && armed.CompareAndSwap(true, false) {
			stored <- struct{}{}
			select {
			case <-release:
			case <-resp.Request.Context().Done():
			}
			resp.Body.Close()
			return dropped
		}
		return nil
	}
	reverse.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		if errors.Is(e, dropped) {
			if h, ok := w.(http.Hijacker); ok {
				conn, _, err := h.Hijack()
				if err == nil {
					conn.Close()
				}
			}
			return
		}
		w.WriteHeader(503)
	}
	proxyServer = httptest.NewTLSServer(reverse)
	t.Cleanup(proxyServer.Close)
	ca := filepath.Join(t.TempDir(), "proxy-ca.pem")
	if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxyServer.Certificate().Raw}), 0600); e != nil {
		t.Fatal("proxy CA fixture failed")
	}
	proxyCfg := base
	proxyCfg.registry = strings.TrimPrefix(proxyServer.URL, "https://")
	proxyCfg.plain = false
	proxyCfg.ca = ca
	return proxyCfg, proxyServer, armed, stored, release
}
func integrationCrash(t *testing.T, cfg integrationConfig, root integrationTarget, v delivery.Verified, indexPath, nonce, dir string, image Descriptor, trace *integrationTrace, doc *integrationEvidence) (string, integrationTarget) {
	t.Helper()
	var subject *Descriptor
	if cfg.referrers == "required" {
		d := integrationSeedIndex(t, root.client, image, nonce, "crash")
		subject = &d
	}
	proxyCfg, server, armed, stored, release := integrationCrashProxy(t, cfg, root.client, trace)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	target := integrationTargetFor(t, proxyCfg, v, subject, false, trace, "crash-recovery", dir)
	journal := filepath.Join(dir, "crash-journal")
	input := integrationChild{Index: indexPath, Journal: journal, ArtifactID: v.Source().ArtifactID, Description: target.description, ConfigSHA256: target.configSHA256, ExpectedReferences: expected(target.client.options)}
	inputPath := filepath.Join(dir, "child-input.json")
	os.WriteFile(inputPath, mustJSON(input), 0600)
	exe, e := os.Executable()
	if e != nil {
		t.Fatal("child executable unavailable")
	}
	cmd := exec.Command(exe, "-test.run=^TestIntegrationOCI$")
	cmd.Env = append(os.Environ(), "RIO_OCI_TEST_CHILD=1", "RIO_OCI_TEST_CHILD_INPUT="+inputPath)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	armed.Store(true)
	if e = cmd.Start(); e != nil {
		t.Fatal("integration child could not start")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-stored:
	case <-done:
		diagnostic := "unknown"
		for _, code := range []string{"unsafe_location", "auth_origin_refused", "auth_scope_refused", "upload_rejected", "transport_unavailable", "content_unavailable", "invalid_record"} {
			if strings.Contains(output.String(), code+":") {
				diagnostic = code
				break
			}
		}
		t.Fatalf("integration child stopped before upstream manifest acceptance (%s)", diagnostic)
	case <-time.After(60 * time.Second):
		cmd.Process.Kill()
		<-done
		t.Fatal("integration child did not reach upstream manifest acceptance")
	}
	if e = cmd.Process.Kill(); e != nil {
		t.Fatal("integration child could not be terminated")
	}
	if e = <-done; e == nil {
		t.Fatal("integration child unexpectedly succeeded")
	}
	close(release)
	if _, e = record.Read(journal); e == nil {
		t.Fatal("stale integration crash lock was silently ignored")
	}
	if e = os.Remove(journal + ".lock"); e != nil {
		t.Fatal("explicit owned crash-lock cleanup failed")
	}
	s, e := record.Read(journal)
	if e != nil || len(s.Events) != 1 || s.Disposition != "unknown" {
		t.Fatal("crash did not leave an intent-only history")
	}
	rawIntent, e := os.ReadFile(filepath.Join(journal, "00000000000000000000.json"))
	if e != nil {
		t.Fatal("crash intent unavailable")
	}
	if e = os.Remove(indexPath); e != nil {
		t.Fatal("original index removal failed")
	}
	if e = os.Remove(filepath.Join(filepath.Dir(indexPath), integrationSourceName(v.Source().ArtifactID))); e != nil {
		t.Fatal("original SBOM removal failed")
	}
	r := integrationReconcile(t, target, journal)
	if r.Acknowledgment != "unknown" {
		t.Fatal("recovery fabricated historical acknowledgment")
	}
	after, _ := os.ReadFile(filepath.Join(journal, "00000000000000000000.json"))
	if !bytes.Equal(rawIntent, after) {
		t.Fatal("recovery changed intent bytes")
	}
	manifest, _ := integrationFetch(t, root.client, "manifests/"+target.client.options.Publication.Manifest.Digest, DocumentLimit)
	if string(manifest) != target.client.options.Publication.ManifestJSON {
		t.Fatal("upstream crash content was not independently retrievable")
	}
	scenario := integrationResult("actual-child-crash-after-upstream-201", r, target)
	scenario.ProxyObservedHTTPStatus = 201
	scenario.Outcome = "intent-only recovery verified; acknowledgment remains unknown"
	doc.Scenarios = append(doc.Scenarios, scenario)
	before := trace.writes()
	result, e := runner.Submit(context.Background(), integrationPrepared(target, v), journal)
	if e == nil || result.ExitCode != 2 || trace.writes() != before {
		t.Fatal("crash journal reuse issued a write")
	}
	_ = server
	return journal, target
}

func TestIntegrationOCI(t *testing.T) {
	if os.Getenv("RIO_OCI_TEST_CHILD") == "1" {
		integrationChildRun(t)
		return
	}
	if os.Getenv("RIO_OCI_INTEGRATION") != "1" {
		t.Skip("set RIO_OCI_INTEGRATION=1 only for a dedicated disposable OCI repository")
	}
	cfg, e := integrationSettings(os.Getenv)
	if e != nil {
		t.Fatal("integration environment refused", e)
	}
	if cfg.product == "" || cfg.version == "" || !strings.HasPrefix(cfg.image, "sha256:") || !delivery.ValidDigest(strings.TrimPrefix(cfg.image, "sha256:")) {
		t.Fatal("explicit setup-reported product/version/image digest required")
	}
	trace := &integrationTrace{}
	doc := integrationEvidence{SchemaVersion: 1, Kind: "rio-oci-integration-observations", RealRegistry: true, SyntheticContent: true, ReferrersExpectation: cfg.referrers, Product: cfg.product, Version: cfg.version, ImageDigest: cfg.image, Registry: cfg.registry, Repository: cfg.repository, Auth: cfg.auth, TLS: !cfg.plain, CustomCA: cfg.ca != "", ImmutablePolicy: cfg.immutable, DeniedCanRead: cfg.deniedCanRead, Scenarios: []integrationScenario{}, Requests: []integrationRequest{}}
	t.Cleanup(func() {
		doc.Complete = !t.Failed()
		doc.Requests = trace.copy()
		if cfg.evidencePath == "" {
			return
		}
		raw, e := json.MarshalIndent(doc, "", "  ")
		if e != nil {
			t.Error("evidence serialization failed")
			return
		}
		for _, secret := range cfg.canaries {
			if strings.Contains(string(raw), secret) {
				t.Error("credential canary found; evidence not written")
				return
			}
		}
		f, e := os.OpenFile(cfg.evidencePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			t.Error("new evidence output path unavailable")
			return
		}
		_, e = f.Write(append(raw, '\n'))
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			t.Error("evidence output failed")
		}
	})
	v, indexPath, nonce := integrationInput(t)
	dir := filepath.Dir(indexPath)
	rawIndex, _ := os.ReadFile(indexPath)
	source, _ := os.ReadFile(filepath.Join(dir, "bom.json"))
	variants := map[string]delivery.Verified{}
	for _, id := range []string{"conflict", "denied", "crash"} {
		verified, e := delivery.Verify(indexPath, id, false)
		if e != nil {
			t.Fatal("integration variant verification failed")
		}
		variants[id] = verified
	}
	root := integrationTargetFor(t, cfg, v, nil, false, trace, "fixture-setup", dir)
	integrationReadiness(t, root.client)
	imageConfig := mustJSON(map[string]any{"architecture": "amd64", "os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": []string{}}, "config": map[string]any{"Labels": map[string]string{"io.rebaze.rio.synthetic-run": nonce}}})
	configDescriptor := integrationSeedBlob(t, root.client, imageConfig, "application/vnd.oci.image.config.v1+json")
	imageRaw := mustJSON(map[string]any{"schemaVersion": 2, "mediaType": ManifestMediaType, "config": configDescriptor, "layers": []Descriptor{}})
	image := integrationSeedManifest(t, root.client, imageRaw, ManifestMediaType, "rio-integration-image-"+nonce)
	imageIndex := integrationSeedIndex(t, root.client, image, nonce, "index")
	doc.Scenarios = append(doc.Scenarios, integrationScenario{Name: "seed-image-and-index", Manifest: &image, Subject: &imageIndex, Outcome: "stored and descriptor bytes independently hashed"})
	paths := []string{}
	var standalone integrationTarget
	var standalonePath string
	for _, tc := range []struct {
		name    string
		subject *Descriptor
	}{{"standalone", nil}, {"attached-image", &image}, {"attached-index", &imageIndex}} {
		target := integrationTargetFor(t, cfg, v, tc.subject, false, trace, tc.name, dir)
		path := filepath.Join(dir, tc.name+"-journal")
		if tc.subject != nil && cfg.referrers == "unsupported" {
			before := trace.writes()
			r := integrationSubmit(t, target, v, path, 4, "")
			if r.Error == nil || r.Error.Code != "unsupported_referrers" || trace.writes() != before {
				t.Fatal("expected required-API refusal without writes")
			}
			paths = append(paths, path)
			doc.Scenarios = append(doc.Scenarios, integrationResult(tc.name+"-required-api-refusal", r, target))
			continue
		}
		r := integrationSubmit(t, target, v, path, 0, "")
		doc.Scenarios = append(doc.Scenarios, integrationResult(tc.name+"-publication", r, target))
		r = integrationReconcile(t, target, path)
		scenario := integrationResult(tc.name+"-readback", r, target)
		blob, _ := integrationFetch(t, root.client, "blobs/sha256:"+v.Source().OutputSHA256, delivery.PayloadLimit)
		if !bytes.Equal(blob, source) {
			t.Fatal("independent raw SBOM read-back changed bytes")
		}
		scenario.ReadbackSHA256 = delivery.Digest(blob)
		doc.Scenarios = append(doc.Scenarios, scenario)
		paths = append(paths, path)
		if tc.subject == nil {
			standalone = target
			standalonePath = path
		}
	}
	before := trace.writes()
	retryPath := filepath.Join(dir, "retry-journal")
	r := integrationSubmit(t, standalone, v, retryPath, 0, standalonePath)
	if trace.writes() != before || r.Verification != "verified" {
		t.Fatal("already-present retry wrote content or omitted verification")
	}
	paths = append(paths, retryPath)
	doc.Scenarios = append(doc.Scenarios, integrationResult("explicit-already-present-retry", r, standalone))
	conflict := integrationTargetFor(t, cfg, variants["conflict"], nil, false, trace, "tag-conflict", dir)
	integrationSeedManifest(t, conflict.client, imageRaw, ManifestMediaType, conflict.client.options.Publication.Tag)
	before = trace.writes()
	conflictPath := filepath.Join(dir, "conflict-journal")
	r = integrationSubmit(t, conflict, variants["conflict"], conflictPath, 4, "")
	if trace.writes() != before {
		t.Fatal("tag conflict mutated registry")
	}
	paths = append(paths, conflictPath)
	doc.Scenarios = append(doc.Scenarios, integrationResult("generated-tag-conflict-no-write", r, conflict))
	// Probe the declared server immutability policy only on a fresh synthetic tag.
	immutableTag := "rio-integration-policy-" + nonce
	integrationSeedManifest(t, root.client, imageRaw, ManifestMediaType, immutableTag)
	changed := mustJSON(map[string]any{"schemaVersion": 2, "mediaType": ManifestMediaType, "config": configDescriptor, "layers": []Descriptor{}, "annotations": map[string]string{"io.rebaze.rio.synthetic-case": "overwrite-probe"}})
	changedDesc := Descriptor{ManifestMediaType, "sha256:" + delivery.Digest(changed), int64(len(changed))}
	ctx, cancel := root.client.traversal(context.Background(), true)
	overwriteErr := root.client.repo.Manifests().PushReference(ctx, ociDescriptor(changedDesc), bytes.NewReader(changed), immutableTag)
	overwriteStatus := status(ctx)
	cancel()
	if cfg.immutable && overwriteErr == nil {
		t.Fatal("configured immutable tag accepted replacement")
	}
	if !cfg.immutable && overwriteErr != nil {
		t.Fatalf("mutable server overwrite probe failed (HTTP %d)", overwriteStatus)
	}
	got, _ := integrationFetch(t, root.client, "manifests/"+immutableTag, DocumentLimit)
	want := changed
	outcome := "mutable synthetic tag replacement observed"
	if cfg.immutable {
		want = imageRaw
		outcome = "immutable tag rejected replacement and original remained"
	}
	if !bytes.Equal(got, want) {
		t.Fatal("tag policy read-back contradicted response")
	}
	doc.Scenarios = append(doc.Scenarios, integrationScenario{Name: "server-tag-policy", HTTPStatus: overwriteStatus, Outcome: outcome})
	if cfg.auth != "anonymous" {
		denied := integrationTargetFor(t, cfg, variants["denied"], nil, true, trace, "denied", dir)
		path := filepath.Join(dir, "denied-journal")
		r = integrationSubmit(t, denied, variants["denied"], path, 5, "")
		if cfg.deniedCanRead {
			readOK, writeDenied := false, false
			for _, fact := range trace.copy() {
				if fact.Operation == "denied" && (fact.Method == "GET" || fact.Method == "HEAD") && strings.Contains(fact.Path, "/blobs/") && fact.Status == 200 {
					readOK = true
				}
				if fact.Operation == "denied" && (fact.Method == "PUT" || fact.Method == "POST") && (fact.Status == 401 || fact.Status == 403) {
					writeDenied = true
				}
			}
			if !readOK || !writeDenied {
				t.Fatal("declared read-only credentials did not demonstrate read success and write denial")
			}
		}
		paths = append(paths, path)
		doc.Scenarios = append(doc.Scenarios, integrationResult("separate-denied-credential-set", r, denied))
	}
	crashPath, crashTarget := integrationCrash(t, cfg, root, variants["crash"], indexPath, nonce, dir, image, trace, &doc)
	paths = append(paths, crashPath)
	savedIndex := filepath.Join(dir, "captured-index.json")
	os.WriteFile(savedIndex, rawIndex, 0600)
	collected, e := evidence.Collect(savedIndex, paths, "integration", ValidateSnapshot, func(a, b record.Intent) error {
		if !SamePolicy(a.Destination, b.Destination, false) {
			return invalid("integration retry policy")
		}
		return nil
	})
	if e != nil {
		t.Fatal("real-registry evidence collection failed", safeError(e))
	}
	raw, e := evidence.Marshal(collected)
	if e != nil {
		t.Fatal("real-registry evidence serialization failed", safeError(e))
	}
	for _, path := range paths {
		os.RemoveAll(path)
	}
	os.Remove(savedIndex)
	os.Remove(filepath.Join(dir, "rio.yaml"))
	for _, id := range []string{"app", "conflict", "denied", "crash"} {
		os.Remove(filepath.Join(dir, integrationSourceName(id)))
	}
	os.Remove(crashTarget.client.options.CAFile)
	if _, e = evidence.Parse(raw, ValidateSnapshot, func(a, b record.Intent) error {
		if !SamePolicy(a.Destination, b.Destination, false) {
			return invalid("integration retry policy")
		}
		return nil
	}); e != nil {
		t.Fatal("portable real-registry evidence inspection failed", safeError(e))
	}
	doc.RecordSHA256 = delivery.Digest(raw)
	doc.RecordBytes = len(raw)
	t.Logf("Observed %d real-registry scenarios; raw read-back, declared Referrers profile and actual child-crash recovery passed", len(doc.Scenarios))
}
