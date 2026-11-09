package dtrack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/rebaze/rio/internal/delivery"
)

const pairBinding = "project: {name: app, version: '1'}\nautoCreate: true"

func describeOptions(t *testing.T, dst, binding string) (Options, error) {
	t.Helper()
	d, e := (Provider{}).Describe(node(t, "url: https://example.test\n"+dst), node(t, binding), delivery.Subject{Name: "app", Version: "1"})
	if e != nil {
		return Options{}, e
	}
	o, _, e := ValidateDescription(d)
	if e != nil {
		t.Fatalf("persisted description invalid: %v", e)
	}
	return o, nil
}

func TestDescribeProjectFields(t *testing.T) {
	o, e := describeOptions(t, "tags: [owner:payments, rio-it]\nparent: {name: Payments, version: all}\nisLatest: true", pairBinding)
	if e != nil {
		t.Fatal(e)
	}
	want := Options{Tags: &[]string{"owner:payments", "rio-it"}, Parent: &Parent{Name: "Payments", Version: "all"}, IsLatest: ptr(true)}
	if diff := cmp.Diff(want, Options{Tags: o.Tags, Parent: o.Parent, IsLatest: o.IsLatest}); diff != "" {
		t.Fatal(diff)
	}
	// Tags stay valid with every selector, including UUID.
	if _, e := describeOptions(t, "tags: [rio-it]", "project: {uuid: f90934f5-cb88-47ce-81cb-db06fc67d4b4}"); e != nil {
		t.Fatal(e)
	}
	if _, e := describeOptions(t, "parent: {uuid: F90934F5-CB88-47CE-81CB-DB06FC67D4B4}", "project: {fromSubject: true}\nautoCreate: true"); e != nil {
		t.Fatal(e)
	}
}

func TestDescribeOmittedProjectFieldsKeepTheDescription(t *testing.T) {
	d, e := (Provider{}).Describe(node(t, "url: https://example.test"), node(t, pairBinding), delivery.Subject{})
	if e != nil {
		t.Fatal(e)
	}
	if want := `{"url":"https://example.test","apiKeyEnv":"DTRACK_API_KEY","allowHTTP":false,"project":{"name":"app","version":"1"},"autoCreate":true}`; string(d.Options) != want {
		t.Fatalf("options = %s", d.Options)
	}
}

func TestDescribeArtifactOverrideReplacesProjectFields(t *testing.T) {
	o, e := describeOptions(t, "tags: [shared]\nisLatest: false\nautoCreate: true", "project: {name: app, version: '1'}\ntags: [owner:payments]\nisLatest: true\nparent: {uuid: f90934f5-cb88-47ce-81cb-db06fc67d4b4}")
	if e != nil {
		t.Fatal(e)
	}
	if diff := cmp.Diff([]string{"owner:payments"}, *o.Tags); diff != "" || !*o.IsLatest || o.Parent.UUID != "f90934f5-cb88-47ce-81cb-db06fc67d4b4" {
		t.Fatalf("override not applied: %+v %s", o, diff)
	}
}

func TestDescribeRejectsProjectFields(t *testing.T) {
	for _, tc := range []struct{ name, dst, binding, want string }{
		{"duplicate tag", "tags: [a, a]", pairBinding, "tags"},
		{"blank tag", "tags: ['']", pairBinding, "tags"},
		{"edge space", "tags: [' a']", pairBinding, "tags"},
		{"comma", "tags: ['a,b']", pairBinding, "tags"},
		{"uppercase", "tags: [Owner]", pairBinding, "lowercase"},
		{"control", "tags: [\"a\\tb\"]", pairBinding, "tags"},
		{"long", "tags: [" + strings.Repeat("a", 256) + "]", pairBinding, "tags"},
		{"empty list", "tags: []", pairBinding, "tags"},
		{"not a list", "tags: a", pairBinding, "tags"},
		{"number", "tags: [1]", pairBinding, "tags"},
		{"parent both", "parent: {uuid: f90934f5-cb88-47ce-81cb-db06fc67d4b4, name: p, version: '1'}", pairBinding, "parent"},
		{"parent name only", "parent: {name: p}", pairBinding, "parent"},
		{"parent version only", "parent: {version: '1'}", pairBinding, "parent"},
		{"parent bad uuid", "parent: {uuid: nope}", pairBinding, "parent.uuid"},
		{"parent unknown key", "parent: {name: p, version: '1', id: 3}", pairBinding, "parent"},
		{"parent empty", "parent: {}", pairBinding, "parent"},
		{"parent uuid selector", "parent: {name: p, version: '1'}", "project: {uuid: f90934f5-cb88-47ce-81cb-db06fc67d4b4}", "autoCreate"},
		{"parent without autoCreate", "parent: {name: p, version: '1'}", "project: {name: app, version: '1'}", "autoCreate"},
		{"parent autoCreate false", "parent: {name: p, version: '1'}", "project: {name: app, version: '1'}\nautoCreate: false", "autoCreate"},
		{"latest uuid selector", "isLatest: true", "project: {uuid: f90934f5-cb88-47ce-81cb-db06fc67d4b4}", "autoCreate"},
		{"latest without autoCreate", "isLatest: true", "project: {fromSubject: true}", "autoCreate"},
		{"latest string", "isLatest: 'yes'", pairBinding, "isLatest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, e := describeOptions(t, tc.dst, tc.binding)
			if e == nil || !strings.Contains(e.Error(), tc.want) {
				t.Fatalf("error = %v; want %q", e, tc.want)
			}
		})
	}
}

func TestPersistedDescriptionRejectsNoncanonicalProjectFields(t *testing.T) {
	d, e := (Provider{}).Describe(node(t, "url: https://example.test\ntags: [a]"), node(t, pairBinding), delivery.Subject{})
	if e != nil {
		t.Fatal(e)
	}
	var o Options
	json.Unmarshal(d.Options, &o)
	o.Tags = &[]string{"A"}
	d.Options, _ = json.Marshal(o)
	if _, _, e := ValidateDescription(d); e == nil {
		t.Fatal("invalid persisted tags accepted")
	}
}

func ptr[T any](v T) *T { return &v }

// fieldsServer is a synthetic receiver: it records the upload form and answers
// the read-back with project, or with status when project is empty.
type fieldsServer struct {
	form        map[string]string
	reads       []string
	uploadCode  int
	readStatus  int
	readProject string
}

func (f *fieldsServer) start(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			mr, e := r.MultipartReader()
			if e != nil {
				t.Error(e)
				return
			}
			f.form = map[string]string{}
			for {
				p, e := mr.NextPart()
				if e != nil {
					break
				}
				if p.FormName() != "bom" {
					b, _ := io.ReadAll(p)
					f.form[p.FormName()] = string(b)
				}
			}
			code := f.uploadCode
			if code == 0 {
				code = 200
			}
			w.WriteHeader(code)
			if code == 200 {
				io.WriteString(w, `{"token":"`+token+`"}`)
			}
			return
		}
		f.reads = append(f.reads, r.URL.RequestURI())
		if r.Header.Get("X-Api-Key") != canary {
			t.Error("read-back without key")
		}
		status := f.readStatus
		if status == 0 {
			status = 200
		}
		w.WriteHeader(status)
		io.WriteString(w, f.readProject)
	}))
	t.Cleanup(s.Close)
	return s
}

func fieldsTarget(t *testing.T, s *httptest.Server, dst, binding string) delivery.Target {
	t.Helper()
	d, e := (Provider{}).Describe(node(t, "url: "+s.URL+"/prefix\nallowHTTP: true\n"+dst), node(t, binding), delivery.Subject{Name: "app", Version: "1"})
	if e != nil {
		t.Fatal(e)
	}
	target, e := (Provider{}).Build(d, func(string) (string, bool) { return canary, true })
	if e != nil {
		t.Fatal(e)
	}
	return target
}

func submitFacts(t *testing.T, target delivery.Target) (delivery.Submission, *ProjectFacts, error) {
	t.Helper()
	sub, e := target.Submit(context.Background(), payload(t).Payloads())
	if e == nil {
		if err := ValidateSubmission(sub); err != nil {
			t.Fatalf("adapter produced an invalid submission: %v", err)
		}
	}
	facts, err := ReadProject(sub.Observations[0])
	if err != nil {
		t.Fatal(err)
	}
	return sub, facts, e
}

const appliedProject = `{"uuid":"` + token + `","name":"app","version":"1","tags":[{"name":"owner:payments"},{"name":"rio-it"}],"parent":{"uuid":"0b7e5c4e-8f0a-4c43-9d4c-3a1d2c1b0a99","name":"Payments","version":"all"},"isLatest":true,"metrics":{"critical":0}}`

func TestSubmitSendsProjectFieldsAndObservesThem(t *testing.T) {
	f := &fieldsServer{readProject: appliedProject}
	s := f.start(t)
	_, facts, e := submitFacts(t, fieldsTarget(t, s, "tags: [rio-it, owner:payments]\nparent: {name: Payments, version: all}\nisLatest: true", pairBinding))
	if e != nil {
		t.Fatal(e)
	}
	wantForm := map[string]string{"projectName": "app", "projectVersion": "1", "autoCreate": "true", "projectTags": "rio-it,owner:payments", "parentName": "Payments", "parentVersion": "all", "isLatest": "true"}
	if diff := cmp.Diff(wantForm, f.form); diff != "" {
		t.Fatal(diff)
	}
	// The lookup by name omits the parent, so the project is read by UUID too.
	if diff := cmp.Diff([]string{"/prefix/api/v1/project/lookup?name=app&version=1", "/prefix/api/v1/project/" + token}, f.reads); diff != "" {
		t.Fatal(diff)
	}
	want := &ProjectFacts{ReadBack: "read", HTTPStatus: 200,
		Tags:     &TagsFact{Requested: []string{"rio-it", "owner:payments"}, State: "observed"},
		Parent:   &ParentFact{Requested: Parent{Name: "Payments", Version: "all"}, State: "observed"},
		IsLatest: &LatestFact{Requested: true, State: "observed"}}
	if diff := cmp.Diff(want, facts); diff != "" {
		t.Fatal(diff)
	}
}

func TestSubmitRecordsTagsNotAppliedAsDifferent(t *testing.T) {
	// 200 without PORTFOLIO_MANAGEMENT(_UPDATE): the server keeps the old tags.
	f := &fieldsServer{readProject: `{"uuid":"` + token + `","name":"app","version":"1","tags":[{"name":"legacy"}],"isLatest":false}`}
	s := f.start(t)
	_, facts, e := submitFacts(t, fieldsTarget(t, s, "tags: [owner:payments]\nisLatest: true", pairBinding))
	if e != nil {
		t.Fatal(e)
	}
	want := &ProjectFacts{ReadBack: "read", HTTPStatus: 200,
		Tags:     &TagsFact{Requested: []string{"owner:payments"}, State: "different", Observed: &[]string{"legacy"}},
		IsLatest: &LatestFact{Requested: true, State: "different", Observed: ptr(false)}}
	if diff := cmp.Diff(want, facts); diff != "" {
		t.Fatal(diff)
	}
}

func TestSubmitParentByUUIDAndMissingParent(t *testing.T) {
	parent := "0b7e5c4e-8f0a-4c43-9d4c-3a1d2c1b0a99"
	f := &fieldsServer{readProject: appliedProject}
	s := f.start(t)
	_, facts, e := submitFacts(t, fieldsTarget(t, s, "parent: {uuid: "+parent+"}", pairBinding))
	if e != nil || f.form["parentUUID"] != parent || f.form["parentName"] != "" || facts.Parent.State != "observed" {
		t.Fatalf("form=%v facts=%+v err=%v", f.form, facts, e)
	}
	f = &fieldsServer{uploadCode: 404}
	s = f.start(t)
	sub, _, e := submitFacts(t, fieldsTarget(t, s, "parent: {name: Payments, version: all}", pairBinding))
	var de *delivery.Error
	if !errors.As(e, &de) || de.Code != "parent_not_found" || !strings.Contains(de.Message, "parent name=Payments version=all") {
		t.Fatalf("error = %v", e)
	}
	if sub.Disposition != "rejected" || sub.Observations[0].Code != "parent_not_found" || len(f.reads) != 0 {
		t.Fatalf("submission = %+v, reads %v", sub, f.reads)
	}
	if err := ValidateSubmission(sub); err != nil {
		t.Fatal(err)
	}
}

func TestSubmitReadBackUnknownWithoutViewPermission(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		code   string
	}{{403, "", "forbidden"}, {401, "", "forbidden"}, {404, "", "not-found"}, {503, "", "transient"}, {200, "not json", "invalid-response"}, {200, `{"uuid":"` + token + `","tags":"x"}`, "invalid-response"}} {
		t.Run(fmt.Sprint(tc.status, tc.code), func(t *testing.T) {
			f := &fieldsServer{readStatus: tc.status, readProject: tc.body}
			s := f.start(t)
			sub, facts, e := submitFacts(t, fieldsTarget(t, s, "tags: [rio-it]", pairBinding))
			if e != nil || sub.Disposition != "accepted" {
				t.Fatalf("a failed read-back must not fail the accepted upload: %v %+v", e, sub)
			}
			want := &ProjectFacts{ReadBack: tc.code, HTTPStatus: tc.status, Tags: &TagsFact{Requested: []string{"rio-it"}, State: "unknown"}}
			if diff := cmp.Diff(want, facts); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestSubmitWithoutProjectFieldsSendsAndReadsNothingNew(t *testing.T) {
	for _, binding := range []string{pairBinding, "project: {uuid: " + token + "}"} {
		f := &fieldsServer{}
		s := f.start(t)
		sub, facts, e := submitFacts(t, fieldsTarget(t, s, "", binding))
		if e != nil || facts != nil || len(f.reads) != 0 || sub.Observations[0].Details != nil {
			t.Fatalf("facts=%+v reads=%v details=%s err=%v", facts, f.reads, sub.Observations[0].Details, e)
		}
		for _, key := range []string{"projectTags", "parentUUID", "parentName", "parentVersion", "isLatest"} {
			if _, ok := f.form[key]; ok {
				t.Fatalf("sent unconfigured %s", key)
			}
		}
	}
}

func TestSubmitTagsWithUUIDSelectorReadsTheProjectByUUID(t *testing.T) {
	f := &fieldsServer{readProject: appliedProject}
	s := f.start(t)
	_, facts, e := submitFacts(t, fieldsTarget(t, s, "tags: [owner:payments, rio-it]", "project: {uuid: "+token+"}"))
	if e != nil || f.form["project"] != token || f.form["projectTags"] != "owner:payments,rio-it" || facts.Tags.State != "observed" {
		t.Fatalf("form=%v facts=%+v err=%v", f.form, facts, e)
	}
	if diff := cmp.Diff([]string{"/prefix/api/v1/project/" + token}, f.reads); diff != "" {
		t.Fatal(diff)
	}
}

func TestObserveReadsProjectFieldsBack(t *testing.T) {
	f := &fieldsServer{readProject: appliedProject}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/prefix/api/v1/event/token/") {
			io.WriteString(w, `{"processing":false}`)
			return
		}
		f.reads = append(f.reads, r.URL.RequestURI())
		io.WriteString(w, f.readProject)
	}))
	defer s.Close()
	target := fieldsTarget(t, s, "tags: [owner:payments, rio-it]", pairBinding).(delivery.Observer)
	o, e := target.Observe(context.Background(), []delivery.Reference{{Kind: "dependency-track:event-token", Value: token}})
	if e != nil || o.Value != "not-observed" {
		t.Fatal(o, e)
	}
	facts, e := ReadProject(o)
	if e != nil || facts == nil || facts.Tags.State != "observed" || len(f.reads) != 1 {
		t.Fatalf("facts=%+v err=%v reads=%v", facts, e, f.reads)
	}
	if e := ValidateEvidence(nil, []delivery.Observation{o}); e != nil {
		t.Fatal(e)
	}
}

func TestValidateEvidenceRejectsContradictoryProjectFacts(t *testing.T) {
	for _, facts := range []string{
		`{"readBack":"forbidden","httpStatus":403,"tags":{"requested":["a"],"state":"observed"}}`,
		`{"readBack":"read","httpStatus":200,"tags":{"requested":["a"],"state":"unknown"}}`,
		`{"readBack":"read","httpStatus":200,"tags":{"requested":["a"],"state":"different"}}`,
		`{"readBack":"read","httpStatus":200,"tags":{"requested":["a"],"state":"observed","observed":["a"]}}`,
		`{"readBack":"read","httpStatus":200,"tags":{"requested":["a"],"state":"applied"}}`,
		`{"readBack":"guess","tags":{"requested":["a"],"state":"unknown"}}`,
		`{"readBack":"read","httpStatus":200}`,
	} {
		o := delivery.Observation{Kind: "activity", Value: "not-observed", Origin: "receiver", Code: "activity_observed", HTTPStatus: 200, References: []delivery.Reference{}, Details: json.RawMessage(`{"project":` + facts + `}`)}
		if e := ValidateEvidence(nil, []delivery.Observation{o}); e == nil {
			t.Errorf("accepted %s", facts)
		}
	}
}
