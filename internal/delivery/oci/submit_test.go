package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/delivery/runner"
	"github.com/rebaze/rio/internal/index"
)

func verified(t testing.TB) (delivery.Verified, string) {
	t.Helper()
	dir := t.TempDir()
	raw := []byte("{\n \"bomFormat\": \"CycloneDX\", \"metadata\": {\"component\": {\"name\": \"synthetic\", \"version\": \"1\"}}\n}\n")
	path := filepath.Join(dir, "bom.json")
	os.WriteFile(path, raw, 0600)
	hash := delivery.Digest(raw)
	idx := index.New("test", index.FileRef{Path: "rio.yaml", SHA256: hash})
	idx.Artifacts = []index.Artifact{{ID: "app", Input: index.FileRef{Path: "bom.json", SHA256: hash}, Output: index.FileRef{Path: "bom.json", SHA256: hash}, SpecVersion: index.SpecVersions{Input: "1.6", Output: "1.6"}, Gate: index.GateOK}}
	if _, e := index.Write(dir, idx); e != nil {
		t.Fatal(e)
	}
	v, e := delivery.Verify(filepath.Join(dir, "index.json"), "app", false)
	if e != nil {
		t.Fatal(e)
	}
	return v, path
}

type registryStub struct {
	t                                                                  testing.TB
	mu                                                                 sync.Mutex
	server                                                             *httptest.Server
	blobs, mapManifest                                                 map[string][]byte
	tags                                                               map[string]string
	requests, writes                                                   []string
	failPhase                                                          string
	failStatus                                                         int
	badLocation, badReceipt, missingSubject, noReferrers, dropManifest bool
	intentPath                                                         string
}

func newRegistry(t testing.TB) *registryStub {
	t.Helper()
	s := &registryStub{t: t, blobs: map[string][]byte{}, mapManifest: map[string][]byte{}, tags: map[string]string{}}
	s.server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.server.Close)
	return s
}
func (s *registryStub) error(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	io.WriteString(w, `{"errors":[{"code":"DENIED","message":"`+secretCanary+`"}]}`)
}
func (s *registryStub) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.intentPath != "" {
		if _, e := os.Stat(filepath.Join(s.intentPath, "00000000000000000000.json")); e != nil {
			s.t.Error("HTTP before committed intent")
		}
	}
	s.requests = append(s.requests, r.Method+" "+r.URL.Path)
	write := r.Method != "GET" && r.Method != "HEAD"
	if write {
		s.writes = append(s.writes, r.Method+" "+r.URL.Path)
	}
	if s.failPhase != "" && strings.Contains(r.URL.Path, s.failPhase) {
		s.error(w, s.failStatus)
		return
	}
	if r.URL.Path == "/v2/" {
		w.WriteHeader(200)
		return
	}
	prefix := "/v2/acme/app/"
	path := strings.TrimPrefix(r.URL.Path, prefix)
	if path == r.URL.Path {
		s.t.Error("wrong repository path")
		s.error(w, 404)
		return
	}
	switch {
	case strings.HasPrefix(path, "referrers/"):
		if s.noReferrers {
			s.error(w, 404)
			return
		}
		subject := strings.TrimPrefix(path, "referrers/")
		refs := []map[string]any{}
		for dg, b := range s.mapManifest {
			var m map[string]any
			json.Unmarshal(b, &m)
			sub, _ := m["subject"].(map[string]any)
			if sub != nil && sub["digest"] == subject {
				refs = append(refs, map[string]any{"mediaType": ManifestMediaType, "digest": dg, "size": len(b), "artifactType": SBOMMediaType})
			}
		}
		w.Header().Set("Content-Type", IndexMediaType)
		json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 2, "mediaType": IndexMediaType, "manifests": refs})
	case strings.HasPrefix(path, "manifests/"):
		reference := strings.TrimPrefix(path, "manifests/")
		if r.Method == "PUT" {
			b, _ := io.ReadAll(r.Body)
			dg := "sha256:" + delivery.Digest(b)
			s.mapManifest[dg] = b
			s.tags[reference] = dg
			if s.dropManifest {
				conn, _, _ := w.(http.Hijacker).Hijack()
				conn.Close()
				return
			}
			var m map[string]any
			json.Unmarshal(b, &m)
			if sub, ok := m["subject"].(map[string]any); ok && !s.missingSubject {
				w.Header().Set("OCI-Subject", sub["digest"].(string))
			}
			if !s.badReceipt {
				w.Header().Set("Docker-Content-Digest", dg)
			}
			w.Header().Set("Location", prefix+"manifests/"+dg)
			w.WriteHeader(201)
			return
		}
		dg := reference
		if !strings.HasPrefix(dg, "sha256:") {
			dg = s.tags[reference]
		}
		b, ok := s.mapManifest[dg]
		if !ok {
			s.error(w, 404)
			return
		}
		var m map[string]any
		json.Unmarshal(b, &m)
		media, _ := m["mediaType"].(string)
		w.Header().Set("Content-Type", media)
		w.Header().Set("Docker-Content-Digest", dg)
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		w.Write(b)
	case strings.HasPrefix(path, "blobs/uploads/"):
		if r.Method == "POST" {
			location := prefix + "blobs/uploads/synthetic?state=a%2fb&part=one+two"
			if s.badLocation {
				location = "http://127.0.0.1:1/stolen?" + secretCanary
			}
			w.Header().Set("Location", location)
			w.WriteHeader(202)
			return
		}
		if !strings.HasPrefix(r.URL.RawQuery, "state=a%2fb&part=one+two&digest=") {
			s.t.Error("upload session query changed", r.URL.RawQuery)
		}
		b, _ := io.ReadAll(r.Body)
		dg := "sha256:" + delivery.Digest(b)
		if r.URL.Query().Get("digest") != dg {
			s.t.Error("uploaded digest mismatch")
		}
		s.blobs[dg] = b
		w.Header().Set("Docker-Content-Digest", dg)
		w.Header().Set("Location", prefix+"blobs/"+dg)
		w.WriteHeader(201)
	case strings.HasPrefix(path, "blobs/"):
		dg := strings.TrimPrefix(path, "blobs/")
		b, ok := s.blobs[dg]
		if !ok {
			s.error(w, 404)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Docker-Content-Digest", dg)
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		if r.Method != "HEAD" {
			w.Write(b)
		}
	default:
		s.error(w, 404)
	}
}
func (s *registryStub) seedSubject() Descriptor {
	raw := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	d := Descriptor{IndexMediaType, "sha256:" + delivery.Digest(raw), int64(len(raw))}
	s.mapManifest[d.Digest] = raw
	return d
}
func submitClient(t testing.TB, s *registryStub, v delivery.Verified, subject *Descriptor) *client {
	t.Helper()
	extra := ""
	if subject != nil {
		extra = fmt.Sprintf("subject: {digest: '%s', mediaType: '%s', size: %d}\n", subject.Digest, subject.MediaType, subject.Size)
	}
	d := clientDescription(t, s.server.URL, "{anonymous: true}", extra)
	p, e := (Provider{}).Prepare(d, v.Source(), []delivery.PayloadRef{v.Payloads()[0].Ref()})
	if e != nil {
		t.Fatal(e)
	}
	return buildClient(t, p.Description)
}
func TestSubmitExactSnapshotAndAlreadyPresent(t *testing.T) {
	for _, attached := range []bool{false, true} {
		t.Run(fmt.Sprint(attached), func(t *testing.T) {
			s := newRegistry(t)
			v, path := verified(t)
			var subject *Descriptor
			if attached {
				d := s.seedSubject()
				subject = &d
			}
			c := submitClient(t, s, v, subject)
			original, _ := os.ReadFile(path)
			os.WriteFile(path, []byte("changed"), 0600)
			sub, e := c.Submit(context.Background(), v.Payloads())
			if e != nil || sub.Disposition != "accepted" {
				t.Fatal(sub, e)
			}
			if !bytes.Equal(s.blobs["sha256:"+v.Source().OutputSHA256], original) {
				t.Fatal("snapshot reopened")
			}
			pub := c.options.Publication
			if string(s.mapManifest[pub.Manifest.Digest]) != pub.ManifestJSON {
				t.Fatal("manifest rewritten")
			}
			if len(sub.References) != len(expected(c.options)) {
				t.Fatal(sub)
			}
			writes := len(s.writes)
			sub, e = c.Submit(context.Background(), v.Payloads())
			if e != nil || sub.Disposition != "accepted" || len(s.writes) != writes {
				t.Fatal("already present reuploaded", sub, e)
			}
			found := false
			for _, o := range sub.Observations {
				if o.Code == "already_present" {
					found = true
				}
				if o.Kind == "content" && o.Value != "verified" {
					t.Fatal(o)
				}
			}
			if !found {
				t.Fatal(sub)
			}
		})
	}
}
func TestSubmitNoMutationOnConflictOrSubject(t *testing.T) {
	for _, mode := range []string{"tag", "subject-missing", "subject-size", "referrers"} {
		t.Run(mode, func(t *testing.T) {
			s := newRegistry(t)
			v, _ := verified(t)
			d := s.seedSubject()
			c := submitClient(t, s, v, &d)
			switch mode {
			case "tag":
				other := []byte(`{"schemaVersion":2}`)
				dg := "sha256:" + delivery.Digest(other)
				s.mapManifest[dg] = other
				s.tags[c.options.Publication.Tag] = dg
			case "subject-missing":
				delete(s.mapManifest, d.Digest)
			case "subject-size":
				s.mapManifest[d.Digest] = append(s.mapManifest[d.Digest], ' ')
			case "referrers":
				s.noReferrers = true
			}
			sub, e := c.Submit(context.Background(), v.Payloads())
			if e == nil || sub.Disposition != "unknown" || len(s.writes) != 0 {
				t.Fatal(mode, sub, e, s.writes)
			}
		})
	}
}
func TestSubmitPartialFailuresAndUnusableReceipt(t *testing.T) {
	for _, mode := range []string{"unsafe-location", "bad-receipt", "missing-subject", "drop-response", "403", "500"} {
		t.Run(mode, func(t *testing.T) {
			s := newRegistry(t)
			v, _ := verified(t)
			d := s.seedSubject()
			c := submitClient(t, s, v, &d)
			switch mode {
			case "unsafe-location":
				s.badLocation = true
			case "bad-receipt":
				s.badReceipt = true
			case "missing-subject":
				s.missingSubject = true
			case "drop-response":
				s.dropManifest = true
			case "403":
				s.failPhase = "blobs/uploads/"
				s.failStatus = 403
			case "500":
				s.failPhase = "blobs/uploads/"
				s.failStatus = 500
			}
			sub, e := c.Submit(context.Background(), v.Payloads())
			s.mu.Lock()
			defer s.mu.Unlock()
			if e == nil {
				t.Fatal("failure accepted", mode)
			}
			want := "unknown"
			if mode == "403" {
				want = "rejected"
			}
			if sub.Disposition != want {
				t.Fatal(mode, sub, e)
			}
			raw, _ := json.Marshal(sub)
			if strings.Contains(string(raw), secretCanary) || strings.Contains(e.Error(), secretCanary) {
				t.Fatal("secret leaked")
			}
			if mode == "bad-receipt" || mode == "missing-subject" {
				seen := false
				for _, o := range sub.Observations {
					seen = seen || o.Kind == "acknowledgment" && o.HTTPStatus == 201 && o.Value == "accepted"
				}
				if !seen {
					t.Fatal("positive HTTP lost", sub)
				}
			}
			puts := 0
			for _, r := range s.writes {
				if strings.HasPrefix(r, "PUT ") && strings.Contains(r, "/manifests/") {
					puts++
				}
				if strings.HasPrefix(r, "DELETE") {
					t.Fatal("rollback")
				}
			}
			if puts > 1 {
				t.Fatal("manifest replayed")
			}
		})
	}
}
func TestSubmitIntentBeforeHTTP(t *testing.T) {
	s := newRegistry(t)
	v, _ := verified(t)
	c := submitClient(t, s, v, nil)
	path := filepath.Join(t.TempDir(), "journal")
	s.intentPath = path
	d := description(c.options, "registry")
	p := runner.Prepared{Verified: v, Description: d, ExpectedReferences: expected(c.options), ValidateIntent: ValidateIntent, Intent: record.Intent{RioVersion: "test", Binding: "registry", ConfigSHA256: strings.Repeat("a", 64)}, Target: c}
	r, e := runner.Submit(context.Background(), p, path)
	if e != nil || r.Acknowledgment != "accepted" || !r.Persisted {
		t.Fatal(r, e)
	}
	snap, e := record.Read(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = ValidateSnapshot(snap); e != nil {
		t.Fatal(e)
	}
}

func TestSubmitManifestRejectionSurvivesSDKError(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 405, 409, 413, 415, 422, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := newRegistry(t)
			v, _ := verified(t)
			c := submitClient(t, s, v, nil)
			original := s.server.Config.Handler
			s.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PUT" && strings.Contains(r.URL.Path, "/manifests/") {
					s.error(w, status)
					return
				}
				original.ServeHTTP(w, r)
			})
			sub, e := c.Submit(context.Background(), v.Payloads())
			want := "rejected"
			if status == 429 || status == 500 {
				want = "unknown"
			}
			if e == nil || sub.Disposition != want {
				t.Fatal("SDK erased supported rejection", status, sub, e)
			}
		})
	}
}

func TestSubmitReceiptPersistenceFailurePreservesAcceptance(t *testing.T) {
	s := newRegistry(t)
	v, _ := verified(t)
	c := submitClient(t, s, v, nil)
	path := filepath.Join(t.TempDir(), "journal")
	original := s.server.Config.Handler
	s.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		original.ServeHTTP(w, r)
		if r.Method == "PUT" && strings.Contains(r.URL.Path, "/manifests/") {
			if e := os.Mkdir(filepath.Join(path, "obstruction"), 0700); e != nil {
				t.Error(e)
			}
		}
	})
	p := runner.Prepared{Verified: v, Description: description(c.options, "registry"), ExpectedReferences: expected(c.options), ValidateIntent: ValidateIntent, Intent: record.Intent{RioVersion: "test", Binding: "registry", ConfigSHA256: strings.Repeat("a", 64)}, Target: c}
	r, e := runner.Submit(context.Background(), p, path)
	if e == nil || r.ExitCode != 3 || r.Acknowledgment != "accepted" || !r.RequestMayHaveOccurred || r.Persisted {
		t.Fatal(r, e)
	}
	if _, ok := s.mapManifest[c.options.Publication.Manifest.Digest]; !ok {
		t.Fatal("remote publication missing")
	}
}
func TestSubmitExactMissingBlobAndPartialPhases(t *testing.T) {
	for _, after := range []int{0, 2, 4} {
		t.Run(fmt.Sprint(after), func(t *testing.T) {
			s := newRegistry(t)
			v, _ := verified(t)
			c := submitClient(t, s, v, nil)
			if after == 0 {
				s.blobs[c.options.Publication.Config.Digest] = []byte(emptyConfig)
			}
			original := s.server.Config.Handler
			s.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				s.mu.Lock()
				n := len(s.writes)
				s.mu.Unlock()
				if after > 0 && n >= after && r.Method != "GET" && r.Method != "HEAD" {
					s.error(w, 500)
					return
				}
				original.ServeHTTP(w, r)
			})
			sub, e := c.Submit(context.Background(), v.Payloads())
			if after == 0 {
				if e != nil || len(s.writes) != 3 {
					t.Fatal("existing config uploaded", sub, e, s.writes)
				}
			} else {
				if e == nil || sub.Disposition != "unknown" {
					t.Fatal(sub, e)
				}
				if _, ok := s.blobs[c.options.Publication.Config.Digest]; !ok {
					t.Fatal("completed shared config removed")
				}
				if after == 4 {
					if _, ok := s.blobs["sha256:"+v.Source().OutputSHA256]; !ok {
						t.Fatal("completed SBOM removed")
					}
				}
			}
		})
	}
}
