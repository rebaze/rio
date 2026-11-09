package cli

import (
	"bytes"
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

	"github.com/google/go-cmp/cmp"
	"github.com/rebaze/rio/internal/receipt"
)

// fieldsReceiver is a synthetic Dependency-Track: it applies tags only for
// keyed projects in applied, the way a key without PORTFOLIO_MANAGEMENT
// leaves an existing project's tags alone, and serves project read-backs.
type fieldsReceiver struct {
	mu      sync.Mutex
	forms   map[string]map[string]string
	tags    map[string][]string
	applies map[string]bool
	reads   int
}

func (f *fieldsReceiver) start(t *testing.T) *httptest.Server {
	f.forms, f.tags = map[string]map[string]string{}, map[string][]string{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST":
			if e := r.ParseMultipartForm(1 << 20); e != nil {
				t.Error(e)
				return
			}
			defer r.MultipartForm.RemoveAll()
			form := map[string]string{}
			for k, v := range r.MultipartForm.Value {
				form[k] = v[0]
			}
			name := form["projectName"]
			f.forms[name] = form
			if form["parentName"] == "missing" {
				w.WriteHeader(404)
				return
			}
			if f.applies[name] {
				f.tags[name] = strings.Split(form["projectTags"], ",")
			} else if f.tags[name] == nil {
				f.tags[name] = []string{"legacy"}
			}
			io.WriteString(w, `{"token":"11111111-1111-4111-8111-111111111111"}`)
		case strings.HasPrefix(r.URL.Path, "/api/v1/event/token/"):
			io.WriteString(w, `{"processing":false}`)
		case r.URL.Path == "/api/v1/project/lookup":
			f.reads++
			name := r.URL.Query().Get("name")
			tags := []map[string]string{}
			for _, tag := range f.tags[name] {
				tags = append(tags, map[string]string{"name": tag})
			}
			b, _ := json.Marshal(map[string]any{"uuid": "22222222-2222-4222-8222-222222222222", "name": name, "version": "1.0.0", "tags": tags, "isLatest": true})
			w.Write(b)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func fieldsProject(t *testing.T, url, target string) string {
	t.Helper()
	dir := pipelineFixture(t, "")
	man := "version: 1\nartifacts:\n  - id: api\n    sbom: api.cdx.json\n  - id: worker\n    sbom: worker.cdx.json\n" +
		"delivery:\n  targets:\n    security:\n      type: dependency-track\n      url: " + url + "\n      allowHTTP: true\n      autoCreate: true\n" + target
	if e := os.WriteFile(filepath.Join(dir, "rio.yaml"), []byte(man), 0600); e != nil {
		t.Fatal(e)
	}
	return dir
}

const fieldsTarget = "      tags: [owner:payments, rio-it]\n      isLatest: true\n      overrides:\n        worker:\n          tags: [owner:platform]\n"

func TestPlanShowsEffectiveProjectFieldsOffline(t *testing.T) {
	dir := fieldsProject(t, "http://127.0.0.1:1", fieldsTarget)
	t.Chdir(dir)
	var out, errout bytes.Buffer
	if code := Main([]string{"plan", "--json"}, &out, &errout); code != 0 {
		t.Fatalf("plan: %d %s", code, errout.String())
	}
	var plan struct {
		Delivery struct {
			Pairs []struct {
				ArtifactID    string                 `json:"artifactId"`
				ProjectFields *receipt.ProjectFields `json:"projectFields"`
			} `json:"pairs"`
		} `json:"delivery"`
	}
	if e := json.Unmarshal(out.Bytes(), &plan); e != nil {
		t.Fatal(e)
	}
	got := map[string]*receipt.ProjectFields{}
	for _, p := range plan.Delivery.Pairs {
		got[p.ArtifactID] = p.ProjectFields
	}
	latest := &receipt.ProjectLatestField{Requested: true, State: "unknown"}
	want := map[string]*receipt.ProjectFields{
		"api":    {ReadBack: "not-attempted", Tags: &receipt.ProjectTagsField{Requested: []string{"owner:payments", "rio-it"}, State: "unknown"}, IsLatest: latest},
		"worker": {ReadBack: "not-attempted", Tags: &receipt.ProjectTagsField{Requested: []string{"owner:platform"}, State: "unknown"}, IsLatest: latest},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}
	out.Reset()
	if code := Main([]string{"plan"}, &out, &errout); code != 0 {
		t.Fatal(errout.String())
	}
	if !strings.Contains(out.String(), "deliver worker → security") || !strings.Contains(out.String(), "tags=owner:platform (unknown) isLatest=true (unknown) readBack=not-attempted") {
		t.Fatalf("plan text:\n%s", out.String())
	}
}

func TestPipelineRecordsObservedAndDifferentProjectFields(t *testing.T) {
	f := &fieldsReceiver{applies: map[string]bool{"api": true}}
	s := f.start(t)
	dir := fieldsProject(t, s.URL, fieldsTarget)
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "SECRET-CANARY-203")
	code, d, path := rootReceipt(t)
	if code != 0 || len(d.Deliveries) != 2 {
		t.Fatalf("code=%d %+v", code, d)
	}
	if f.forms["api"]["projectTags"] != "owner:payments,rio-it" || f.forms["worker"]["projectTags"] != "owner:platform" || f.forms["api"]["isLatest"] != "true" {
		t.Fatalf("forms = %v", f.forms)
	}
	byID := map[string]*receipt.ProjectFields{}
	for _, v := range d.Deliveries {
		if v.State != "accepted" {
			t.Fatalf("delivery %+v", v)
		}
		byID[v.ArtifactID] = v.ProjectFields
	}
	want := map[string]*receipt.ProjectFields{
		"api": {ReadBack: "read", Tags: &receipt.ProjectTagsField{Requested: []string{"owner:payments", "rio-it"}, State: "observed"},
			IsLatest: &receipt.ProjectLatestField{Requested: true, State: "observed"}},
		"worker": {ReadBack: "read", Tags: &receipt.ProjectTagsField{Requested: []string{"owner:platform"}, State: "different", Observed: &[]string{"legacy"}},
			IsLatest: &receipt.ProjectLatestField{Requested: true, State: "observed"}},
	}
	if diff := cmp.Diff(want, byID); diff != "" {
		t.Fatal(diff)
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("SECRET-CANARY")) || bytes.Contains(raw, []byte("22222222-2222")) {
		t.Fatal("receipt retained a secret or response body")
	}
}

func TestPipelineMissingParentIsItsOwnFailure(t *testing.T) {
	f := &fieldsReceiver{}
	s := f.start(t)
	dir := fieldsProject(t, s.URL, "      parent: {name: missing, version: all}\n")
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "synthetic")
	code, d, _ := rootReceipt(t)
	if code == 0 || f.reads != 0 {
		t.Fatalf("code=%d reads=%d", code, f.reads)
	}
	// The first rejection stops the batch, so only api was attempted.
	if d.Deliveries[1].State != "unattempted" {
		t.Fatalf("worker = %+v", d.Deliveries[1])
	}
	for _, v := range d.Deliveries[:1] {
		if v.State != "rejected" || v.ErrorCode != "parent_not_found" || v.ProjectFields.ReadBack != "not-attempted" || v.ProjectFields.Parent.State != "unknown" {
			t.Fatalf("delivery %+v fields %+v", v, v.ProjectFields)
		}
		if v.Responses[0].Code != "parent_not_found" || v.Responses[0].HTTPStatus != 404 {
			t.Fatalf("response %+v", v.Responses)
		}
	}
}

func TestReconcileReadsProjectFieldsBackAndRefusesChangedFields(t *testing.T) {
	f := &fieldsReceiver{}
	s := f.start(t)
	ip, cfg := deliveryFixture(t, s.URL)
	b, _ := os.ReadFile(cfg)
	os.WriteFile(cfg, append(b, []byte("      tags: [rio-it]\n")...), 0600)
	t.Setenv("DTRACK_API_KEY", "synthetic")
	journal := filepath.Join(t.TempDir(), "journal")
	code, r, _ := deliveryRun(t, "deliver", "--index", ip, "--manifest", cfg, "--target", "security", "--record", journal)
	if code != 0 || r["outcome"] != "accepted" {
		t.Fatal(code, r)
	}
	f.applies = map[string]bool{"app": true}
	f.tags["app"] = []string{"rio-it"}
	out := t.TempDir()
	code, r, _ = deliveryRun(t, "delivery", "reconcile", "--record", journal, "--manifest", cfg, "--out", out)
	if code != 0 {
		t.Fatal(code, r)
	}
	pub := r["receipt"].(map[string]any)["path"].(string)
	raw, _ := os.ReadFile(pub)
	d, e := receipt.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	if got := d.Deliveries[0].ProjectFields; got == nil || got.ReadBack != "read" || got.Tags.State != "observed" {
		t.Fatalf("reconcile fields = %+v", got)
	}
	os.WriteFile(cfg, bytes.Replace(append(b, []byte("      tags: [rio-it]\n")...), []byte("[rio-it]"), []byte("[owner:other]"), 1), 0600)
	code, _, stderr := deliveryRun(t, "delivery", "reconcile", "--record", journal, "--manifest", cfg)
	if code != 2 || !strings.Contains(stderr, "destination_drift") {
		t.Fatalf("changed tags not refused: %d %s", code, stderr)
	}
}

func TestDescribeProjectFieldsText(t *testing.T) {
	observed := false
	f := &receipt.ProjectFields{ReadBack: "read", Tags: &receipt.ProjectTagsField{Requested: []string{"a"}, State: "different", Observed: &[]string{}},
		Parent: &receipt.ProjectParentField{Requested: receipt.ProjectParent{Name: "p", Version: "1"}, State: "observed"}, IsLatest: &receipt.ProjectLatestField{Requested: true, State: "different", Observed: &observed}}
	if got, want := describeProjectFields(f), "tags=a (different: ) parent=p@1 (observed) isLatest=true (different: false)"; got != want {
		t.Fatal(fmt.Sprintf("%q != %q", got, want))
	}
}
