package dtrack

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/index"
	"gopkg.in/yaml.v3"
)

// This test MUTATES a dedicated disposable project's inventory. Opt in explicitly.
func TestIntegrationDependencyTrack(t *testing.T) {
	if os.Getenv("RIO_DTRACK_INTEGRATION") != "1" {
		t.Skip("requires explicitly configured disposable Dependency-Track")
	}
	required := func(name string) string {
		t.Helper()
		v := os.Getenv(name)
		if v == "" {
			t.Fatalf("missing %s", name)
		}
		return v
	}
	base := required("RIO_DTRACK_TEST_URL")
	required("RIO_DTRACK_TEST_API_KEY")
	projectUUID := required("RIO_DTRACK_TEST_PROJECT_UUID")
	required("RIO_DTRACK_TEST_DENIED_KEY")
	if !ValidUUID(projectUUID) {
		t.Fatal("invalid dedicated project UUID")
	}
	allowHTTP := os.Getenv("RIO_DTRACK_TEST_ALLOW_HTTP") == "1"
	if strings.HasPrefix(base, "http:") && !allowHTTP {
		t.Fatal("HTTP requires RIO_DTRACK_TEST_ALLOW_HTTP=1")
	}
	dst := map[string]any{"url": base, "apiKeyEnv": "RIO_DTRACK_TEST_API_KEY", "allowHTTP": allowHTTP}
	if ca := os.Getenv("RIO_DTRACK_TEST_CA_FILE"); ca != "" {
		dst["caFile"] = ca
	}
	var dn yaml.Node
	dn.Encode(dst)
	build := func(project map[string]any, auto *bool, env string) *client {
		t.Helper()
		bm := map[string]any{"project": project}
		if auto != nil {
			bm["autoCreate"] = *auto
		}
		var bn yaml.Node
		bn.Encode(bm)
		d, e := (Provider{}).Describe(dn, bn, delivery.Subject{})
		if e != nil {
			t.Fatal(e)
		}
		if env != "" {
			var o Options
			json.Unmarshal(d.Options, &o)
			o.APIKeyEnv = env
			d.Options = mustJSON(o)
			d.CredentialRefs = []string{env}
		}
		target, e := (Provider{}).Build(d, os.LookupEnv)
		if e != nil {
			t.Fatal(e)
		}
		return target.(*client)
	}
	c := build(map[string]any{"uuid": projectUUID}, nil, "")
	read := func(path string, out any) int {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		resp, e := c.request(ctx, "GET", path, "", nil)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			b, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			if e != nil || json.Unmarshal(b, out) != nil {
				t.Fatal("test-harness response invalid")
			}
		}
		return resp.StatusCode
	}
	var version struct {
		Version string `json:"version"`
	}
	if read("/api/version", &version) != 200 || version.Version == "" {
		t.Fatal("server version unavailable")
	}
	var project struct{ Name, Version, UUID string }
	if read("/api/v1/project/"+projectUUID, &project) != 200 || project.Name == "" || project.Version == "" {
		t.Fatal("dedicated project read failed")
	}
	t.Log("disposable server version:", version.Version)
	evidence := integrationEvidence{ServerVersion: version.Version, Sanitized: true, Scenarios: []integrationScenario{}}
	unique := make([]byte, 8)
	if _, e := rand.Read(unique); e != nil {
		t.Fatal("random identity unavailable")
	}
	suffix := hex.EncodeToString(unique)
	boolptr := func(b bool) *bool { return &b }
	verifyInventory := func(uuid, name string) {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for {
			var components []struct{ Name string }
			if read("/api/v1/component/project/"+uuid, &components) == 200 && len(components) == 1 && components[0].Name == name {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("dedicated project inventory did not match submitted synthetic component")
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	run := func(name string, target *client, v delivery.Verified, want string) (delivery.Submission, *integrationScenario) {
		t.Helper()
		scenario := integrationScenario{Name: name, PayloadSHA256: v.Source().OutputSHA256, Requests: []integrationRequest{}}
		target.http.Transport = &evidenceTransport{base: target.http.Transport, scenario: &scenario, project: target.identity.Project, auto: target.options.AutoCreate}
		sub, e := target.Submit(context.Background(), v.Payloads())
		scenario.Interpretation = sub.Disposition
		if sub.Disposition != want {
			t.Fatalf("%s: disposition %s (safe error %v)", name, sub.Disposition, e)
		}
		return sub, &scenario
	}
	for _, mode := range []string{"name-version", "uuid"} {
		component := "rio-integration-" + mode + "-" + suffix
		v := integrationPayload(t, component)
		target := build(map[string]any{"name": project.Name, "version": project.Version}, boolptr(false), "")
		if mode == "uuid" {
			target = build(map[string]any{"uuid": projectUUID}, nil, "")
		}
		sub, scenario := run(mode, target, v, "accepted")
		observer := target
		// Retain observed true/false/status only; never manufacture a transient true.
		for n := 0; n < 40; n++ {
			o, e := observer.Observe(context.Background(), sub.References)
			scenario.Activities = append(scenario.Activities, o.Value)
			if e != nil {
				t.Fatal("real token observation unavailable:", e)
			}
			if o.Value == "not-observed" {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		verifyInventory(projectUUID, component)
		scenario.InventoryVerified = true
		evidence.Scenarios = append(evidence.Scenarios, *scenario)
	}
	absent := "rio-absent-" + suffix
	v := integrationPayload(t, "rio-created-"+suffix)
	_, scenario := run("absent-creation-disabled", build(map[string]any{"name": absent, "version": "1"}, boolptr(false), ""), v, "rejected")
	evidence.Scenarios = append(evidence.Scenarios, *scenario)
	_, scenario = run("absent-creation-enabled", build(map[string]any{"name": absent, "version": "1"}, boolptr(true), ""), v, "accepted")
	var created struct{ UUID string }
	deadline := time.Now().Add(60 * time.Second)
	for read("/api/v1/project/lookup?name="+url.QueryEscape(absent)+"&version=1", &created) != 200 {
		if time.Now().After(deadline) {
			t.Fatal("auto-created project missing")
		}
		time.Sleep(250 * time.Millisecond)
	}
	verifyInventory(created.UUID, "rio-created-"+suffix)
	scenario.InventoryVerified = true
	evidence.Scenarios = append(evidence.Scenarios, *scenario)
	_, scenario = run("denied-permissions", build(map[string]any{"uuid": projectUUID}, nil, "RIO_DTRACK_TEST_DENIED_KEY"), v, "rejected")
	evidence.Scenarios = append(evidence.Scenarios, *scenario)
	t.Setenv("RIO_DTRACK_TEST_INVALID_KEY", "synthetic-invalid-api-key")
	_, scenario = run("invalid-credential", build(map[string]any{"uuid": projectUUID}, nil, "RIO_DTRACK_TEST_INVALID_KEY"), v, "rejected")
	evidence.Scenarios = append(evidence.Scenarios, *scenario)
	observer := build(map[string]any{"uuid": projectUUID}, nil, "")
	scenario = &integrationScenario{Name: "unknown-token", Requests: []integrationRequest{}}
	observer.http.Transport = &evidenceTransport{base: observer.http.Transport, scenario: scenario}
	o, e := observer.Observe(context.Background(), []delivery.Reference{{Kind: "dependency-track:event-token", Value: "00000000-0000-4000-8000-000000000001"}})
	if e != nil || o.Value != "not-observed" {
		t.Fatal("unknown-token contract changed")
	}
	scenario.Interpretation = o.Value
	evidence.Scenarios = append(evidence.Scenarios, *scenario)
	if path := os.Getenv("RIO_DTRACK_EVIDENCE"); path != "" {
		b, _ := json.MarshalIndent(evidence, "", "  ")
		if e = os.WriteFile(path, append(b, '\n'), 0600); e != nil {
			t.Fatal("cannot write sanitized evidence")
		}
	}
}

type integrationEvidence struct {
	ServerVersion string                `json:"serverVersion"`
	Sanitized     bool                  `json:"sanitized"`
	Scenarios     []integrationScenario `json:"scenarios"`
}
type integrationScenario struct {
	Name              string               `json:"name"`
	PayloadSHA256     string               `json:"payloadSHA256,omitempty"`
	Interpretation    string               `json:"interpretation"`
	InventoryVerified bool                 `json:"inventoryVerified,omitempty"`
	Activities        []string             `json:"activities,omitempty"`
	Requests          []integrationRequest `json:"requests"`
}
type integrationRequest struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Form       map[string]string `json:"form,omitempty"`
	HTTPStatus int               `json:"httpStatus"`
	Response   map[string]any    `json:"response"`
}
type evidenceTransport struct {
	base     http.RoundTripper
	scenario *integrationScenario
	project  Project
	auto     *bool
}

func (e *evidenceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := e.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(b))
	if err != nil {
		return resp, err
	}
	r := integrationRequest{Method: req.Method, Path: req.URL.Path, HTTPStatus: resp.StatusCode, Response: map[string]any{}}
	if req.Method == "POST" {
		r.Form = map[string]string{"bom": "<verified-snapshot>"}
		if e.project.UUID != "" {
			r.Form["project"] = "<dedicated-project-uuid>"
		} else {
			r.Form["projectName"] = "<disposable-project-name>"
			r.Form["projectVersion"] = "<test-version>"
			r.Form["autoCreate"] = "false"
			if e.auto != nil && *e.auto {
				r.Form["autoCreate"] = "true"
			}
		}
	}
	if strings.Contains(r.Path, "/event/token/") {
		r.Path = "/api/v1/event/token/<event-token>"
	}
	var raw map[string]any
	if json.Unmarshal(b, &raw) == nil {
		if token, ok := raw["token"].(string); ok && ValidUUID(token) {
			r.Response["token"] = "<event-token>"
		}
		if processing, ok := raw["processing"].(bool); ok {
			r.Response["processing"] = processing
		}
		if status, ok := raw["status"].(string); ok {
			switch status {
			case "CREATED", "RUNNING", "SUSPENDED", "COMPLETED", "FAILED", "CANCELLED":
				r.Response["status"] = status
			}
		}
	}
	e.scenario.Requests = append(e.scenario.Requests, r)
	return resp, nil
}
func integrationPayload(t *testing.T, component string) delivery.Verified {
	t.Helper()
	dir := t.TempDir()
	bom := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "metadata": map[string]any{"component": map[string]any{"type": "application", "name": "rio-disposable-test", "version": "1"}}, "components": []any{map[string]any{"type": "library", "name": component, "version": "1", "purl": "pkg:generic/" + component + "@1"}}}
	b, _ := json.Marshal(bom)
	os.WriteFile(filepath.Join(dir, "bom.json"), b, 0600)
	h := delivery.Digest(b)
	idx := index.New("integration-test", index.FileRef{Path: "rio.yaml", SHA256: h})
	idx.Artifacts = []index.Artifact{{ID: "application", Input: index.FileRef{Path: "bom.json", SHA256: h}, Output: index.FileRef{Path: "bom.json", SHA256: h}, SpecVersion: index.SpecVersions{Input: "1.6", Output: "1.6"}, Gate: index.GateOK}}
	index.Write(dir, idx)
	v, e := delivery.Verify(filepath.Join(dir, "index.json"), "application", false)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
