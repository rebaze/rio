package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/gate"
	"github.com/rebaze/rio/internal/receipt"
)

// runRoot runs the root pipeline in the current directory and returns the exit
// code, the parsed receipt, its run directory and stderr.
func runRoot(t *testing.T, args ...string) (int, receipt.Document, string, string) {
	t.Helper()
	var out, errout bytes.Buffer
	code := Main(append(args, "--json"), &out, &errout)
	var result struct {
		RunDirectory string `json:"runDirectory"`
		Receipt      struct {
			Path string `json:"path"`
		} `json:"receipt"`
	}
	if e := json.Unmarshal(out.Bytes(), &result); e != nil || result.Receipt.Path == "" {
		t.Fatalf("code=%d out=%s err=%s parse=%v", code, out.String(), errout.String(), e)
	}
	raw, e := os.ReadFile(result.Receipt.Path)
	if e != nil {
		t.Fatal(e)
	}
	d, e := receipt.Parse(raw)
	if e != nil {
		t.Fatalf("%v\n%s", e, raw)
	}
	return code, d, result.RunDirectory, errout.String()
}

func appendManifest(t *testing.T, text string) {
	t.Helper()
	f, e := os.OpenFile("rio.yaml", os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = f.WriteString(text); e != nil {
		t.Fatal(e)
	}
}

func TestPipelineSecurityContactRequirement(t *testing.T) {
	const requireContact = "gate:\n  subject:\n    require: [securityContact]\n"
	cases := []struct {
		name        string
		manifest    string
		sbomContact string
		wantCode    int
		wantCalls   int
		wantSubject []string
		wantFailed  []receipt.FailedRequirement
		wantStderr  []string
	}{{
		name:        "not required",
		wantCalls:   2,
		wantSubject: []string{"name", "version"},
	}, {
		name:        "required and missing",
		manifest:    requireContact,
		wantCode:    ExitGate,
		wantSubject: []string{"name", "version", "securityContact"},
		wantFailed:  []receipt.FailedRequirement{{Requirement: "subject.securityContact", Count: 1}},
		wantStderr:  []string{`artifact "api" failed the gate; gate mode fail, so nothing was delivered.`, "subject.securityContact: the SBOM subject has no security-contact reference", "enrichment.subject.securityContact", "Rio does not look it up"},
	}, {
		name:        "required and supplied by reviewed enrichment",
		manifest:    requireContact + "enrichment:\n  subject:\n    securityContact: mailto:security@example.com\n",
		wantCalls:   2,
		wantSubject: []string{"name", "version", "securityContact"},
	}, {
		name:        "required with an unsupported value in the SBOM",
		manifest:    requireContact,
		sbomContact: "security@example.com",
		wantCode:    ExitGate,
		wantSubject: []string{"name", "version", "securityContact"},
		wantFailed:  []receipt.FailedRequirement{{Requirement: "subject.securityContact", Count: 1}},
		wantStderr:  []string{`The security-contact reference "security@example.com" is not an absolute http(s) URL or a mailto address`, "enrichment.replace"},
	}, {
		name:        "warn mode explains and delivers",
		manifest:    "gate:\n  mode: warn\n  subject:\n    require: [securityContact]\n",
		wantCalls:   2,
		wantSubject: []string{"name", "version", "securityContact"},
		wantFailed:  []receipt.FailedRequirement{{Requirement: "subject.securityContact", Count: 1}},
		wantStderr:  []string{"gate mode warn, so the run continues and the receipt records the override."},
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"token":"11111111-1111-4111-8111-111111111111"}`)
			}))
			defer srv.Close()
			dir := pipelineFixture(t, srv.URL)
			t.Chdir(dir)
			t.Setenv("DTRACK_API_KEY", "synthetic")
			for _, id := range []string{"api", "worker"} {
				if tc.sbomContact == "" {
					continue
				}
				raw, _ := os.ReadFile(id + ".cdx.json")
				raw = bytes.Replace(raw, []byte(`"version":"1.0.0"}`), []byte(`"version":"1.0.0","externalReferences":[{"type":"security-contact","url":"`+tc.sbomContact+`"}]}`), 1)
				os.WriteFile(id+".cdx.json", raw, 0600)
			}
			appendManifest(t, tc.manifest)

			code, d, runDir, stderr := runRoot(t)
			if code != tc.wantCode || calls != tc.wantCalls {
				t.Fatalf("exit %d calls %d, want %d and %d\n%s", code, calls, tc.wantCode, tc.wantCalls, stderr)
			}
			for _, a := range d.Artifacts {
				if diff := cmp.Diff(tc.wantSubject, a.Checks.SubjectRequirements); diff != "" {
					t.Errorf("%s subjectRequirements (-want +got):\n%s", a.ID, diff)
				}
				if diff := cmp.Diff(tc.wantFailed, a.Checks.Failed); diff != "" {
					t.Errorf("%s failed (-want +got):\n%s", a.ID, diff)
				}
			}
			for _, s := range tc.wantStderr {
				if !strings.Contains(stderr, s) {
					t.Errorf("stderr lacks %q:\n%s", s, stderr)
				}
			}
			if len(tc.wantStderr) == 0 && strings.Contains(stderr, "failed the gate") {
				t.Errorf("unexpected gate explanation:\n%s", stderr)
			}

			// The index records the opt-in, and its checks survive the strict
			// reader that standalone delivery uses.
			raw, e := os.ReadFile(filepath.Join(runDir, "index.json"))
			if e != nil {
				t.Fatal(e)
			}
			var idx struct {
				Artifacts []struct {
					Checks struct {
						SubjectRequirements []string `json:"subjectRequirements"`
					} `json:"checks"`
				} `json:"artifacts"`
			}
			if e := json.Unmarshal(raw, &idx); e != nil {
				t.Fatal(e)
			}
			want := tc.wantSubject
			if len(want) == 2 {
				want = nil
			}
			if diff := cmp.Diff(want, idx.Artifacts[0].Checks.SubjectRequirements); diff != "" {
				t.Errorf("index subjectRequirements (-want +got):\n%s", diff)
			}
		})
	}
}

// Standalone delivery reports the failed requirements it inherits from the
// index, so the receipt says why the override was needed.
func TestStandaloneDeliverCarriesFailedRequirements(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"11111111-1111-4111-8111-111111111111"}`)
	}))
	defer srv.Close()
	dir := pipelineFixture(t, srv.URL)
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "synthetic")
	appendManifest(t, "gate:\n  subject:\n    require: [securityContact]\n")
	code, _, runDir, _ := runRoot(t)
	if code != ExitGate {
		t.Fatalf("exit %d", code)
	}

	var out, errout bytes.Buffer
	code = Main([]string{"deliver", "--index", filepath.Join(runDir, "index.json"), "--artifact", "api", "--target", "security", "--record", filepath.Join(t.TempDir(), "record"), "--allow-failed-gate", "--json"}, &out, &errout)
	if code != 0 {
		t.Fatalf("deliver exit %d: %s", code, errout.String())
	}
	var result struct {
		Receipt struct {
			Path string `json:"path"`
		} `json:"receipt"`
	}
	if e := json.Unmarshal(out.Bytes(), &result); e != nil {
		t.Fatalf("%v: %s", e, out.String())
	}
	raw, e := os.ReadFile(result.Receipt.Path)
	if e != nil {
		t.Fatal(e)
	}
	d, e := receipt.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	c := d.Artifacts[0].Checks
	if c.Mode != "pre-existing" || !cmp.Equal(c.SubjectRequirements, []string{"name", "version", "securityContact"}) ||
		!cmp.Equal(c.Failed, []receipt.FailedRequirement{{Requirement: "subject.securityContact", Count: 1}}) {
		t.Fatalf("checks %+v", c)
	}
}

// A failing index may not hide the requirement its finding names: dropping
// both the opt-in and its evaluation still leaves the finding, which the
// reader refuses.
func TestIndexRefusesFindingOutsideSelectedRequirements(t *testing.T) {
	dir := pipelineFixture(t, "")
	t.Chdir(dir)
	appendManifest(t, "gate:\n  subject:\n    require: [securityContact]\n")
	code, _, runDir, _ := runRoot(t)
	if code != ExitGate {
		t.Fatalf("exit %d", code)
	}
	original, e := os.ReadFile(filepath.Join(runDir, "index.json"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e := delivery.ParseIndex(original); e != nil {
		t.Fatalf("the written index must be readable: %v", e)
	}
	var idx map[string]any
	if e := json.Unmarshal(original, &idx); e != nil {
		t.Fatal(e)
	}
	checks := idx["artifacts"].([]any)[0].(map[string]any)["checks"].(map[string]any)
	delete(checks, "subjectRequirements")
	evals := checks["evaluations"].([]any)
	checks["evaluations"] = append(evals[:2:2], evals[3:]...)
	raw, e := json.Marshal(idx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := delivery.ParseIndex(raw); e == nil {
		t.Fatal("a security-contact finding without its requirement was accepted")
	}
}

func TestGateExplanationEscapesSBOMText(t *testing.T) {
	r := gate.Result{Findings: []gate.Finding{{Component: "evil\n\x1b[31mrio: all good", Missing: []string{"purl"}}}}
	lines := gateExplanations(r)
	if len(lines) != 1 || strings.ContainsAny(lines[0], "\n\x1b") || !strings.Contains(lines[0], `"evil\n\x1b[31mrio: all good"`) {
		t.Fatalf("SBOM text must be quoted and escaped: %q", lines)
	}
}

// The index's subject requirements must agree with its evaluations and
// findings; a reader refuses an index that claims otherwise.
func TestIndexRefusesContradictorySubjectRequirements(t *testing.T) {
	dir := pipelineFixture(t, "")
	t.Chdir(dir)
	appendManifest(t, "gate:\n  subject:\n    require: [securityContact]\nenrichment:\n  subject:\n    securityContact: https://example.com/security\n")
	code, _, runDir, stderr := runRoot(t)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	original, e := os.ReadFile(filepath.Join(runDir, "index.json"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e := delivery.ParseIndex(original); e != nil {
		t.Fatalf("the written index must be readable: %v", e)
	}
	cases := map[string]func(checks map[string]any){
		"unknown subject requirement": func(c map[string]any) { c["subjectRequirements"] = []any{"name", "version", "license"} },
		"duplicate subject requirement": func(c map[string]any) {
			c["subjectRequirements"] = []any{"name", "version", "securityContact", "securityContact"}
		},
		"name and version left out": func(c map[string]any) { c["subjectRequirements"] = []any{"securityContact"} },
		"evaluation without opt-in": func(c map[string]any) { delete(c, "subjectRequirements") },
		"opt-in without evaluation": func(c map[string]any) {
			evals := c["evaluations"].([]any)
			c["evaluations"] = append(evals[:2:2], evals[3:]...)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			var idx map[string]any
			if e := json.Unmarshal(original, &idx); e != nil {
				t.Fatal(e)
			}
			change(idx["artifacts"].([]any)[0].(map[string]any)["checks"].(map[string]any))
			raw, e := json.Marshal(idx)
			if e != nil {
				t.Fatal(e)
			}
			if _, e := delivery.ParseIndex(raw); e == nil {
				t.Fatal("contradictory subject requirements accepted")
			}
		})
	}
}
