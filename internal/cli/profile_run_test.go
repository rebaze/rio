package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/rebaze/rio/internal/gate"
	"github.com/rebaze/rio/internal/receipt"
)

const profileName = "bsi-tr-03183-2@2.1.0"

// profileRun copies one synthetic fixture next to a manifest, optionally with
// the profile, and runs the root pipeline on it.
func profileRun(t *testing.T, fixture string, withProfile bool) (int, receipt.Document, string, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "profile", fixture))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "in.cdx.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	man := "version: 1\n"
	if withProfile {
		man += "gate:\n  profile: " + profileName + "\n"
	}
	man += "artifacts:\n  - id: cart-api\n    sbom: in.cdx.json\n"
	if err := os.WriteFile(filepath.Join(dir, "rio.yaml"), []byte(man), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	return runRoot(t)
}

func TestGateExplainProfile(t *testing.T) {
	r := gate.Result{
		Profile: &gate.Profile{Name: profileName, Guideline: "BSI TR-03183-2", GuidelineVersion: "2.1.0"},
		Findings: []gate.Finding{
			{SBOM: true, Missing: []string{"creator"}},
			{Subject: true, Missing: []string{"creator"}},
			{Component: "a@1", Missing: []string{"deployableHash", "distributionLicences"}},
			{Component: "b@1", Missing: []string{"deployableHash"}},
		},
	}
	want := []string{
		"sbom.creator (BSI TR-03183-2 2.1.0 §5.2.1): the SBOM has no creator (metadata.manufacturer with a contact email or URL). Set enrichment.producer in rio.yaml, or have the SBOM generator emit one.",
		"subject.creator (BSI TR-03183-2 2.1.0 §5.2.2): the SBOM subject has no creator (manufacturer). Set enrichment.subject.manufacturer in rio.yaml, or have the SBOM generator emit one.",
		`components.distributionLicences (BSI TR-03183-2 2.1.0 §5.2.2, §6.1): 1 component has no concluded licence in SPDX form, for example "a@1". Have the SBOM generator emit it.`,
		`components.deployableHash (BSI TR-03183-2 2.1.0 §5.2.2): 2 components have no SHA-512 hash on a distribution reference, for example "a@1". Have the SBOM generator emit it, add the shipped files with sha512 under distributions in the build context file, or mark components whose file does not exist on its own with rio:tr-03183-2:level. Rio does not hash files.`,
	}
	got := gateExplanations(r)
	// distributionLicences precedes deployableHash in the failed-ID order.
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("lines (-want +got):\n%s", diff)
	}
}

func TestGateExplainProfileLevelAndName(t *testing.T) {
	r := gate.Result{
		Profile: &gate.Profile{Name: profileName, Guideline: "BSI TR-03183-2", GuidelineVersion: "2.1.0"},
		Findings: []gate.Finding{
			{Subject: true, Missing: []string{"level"}, Details: map[string]string{"level": `the rio:tr-03183-2:level value "full" is not logical, identified or assembled`}},
			{Component: "a@1", Missing: []string{"name"}},
		},
	}
	got := strings.Join(gateExplanations(r), "\n")
	for _, s := range []string{
		`subject.level: The rio:tr-03183-2:level value "full" is not logical, identified or assembled. Set it once to logical, identified or assembled, or remove the property.`,
		`components.name (BSI TR-03183-2 2.1.0 §5.2.2): 1 component has no name, for example "a@1". The TR requires it. Have the SBOM generator emit it.`,
	} {
		if !strings.Contains(got, s) {
			t.Errorf("missing %q in:\n%s", s, got)
		}
	}
	if strings.Contains(got, "gate.require") {
		t.Errorf("profile name line must not suggest gate.require:\n%s", got)
	}
}

func TestRootProfileFails(t *testing.T) {
	code, d, runDir, stderr := profileRun(t, "bsi-fail.cdx.json", true)
	if code != ExitGate {
		t.Fatalf("exit %d, want %d\n%s", code, ExitGate, stderr)
	}
	if !strings.Contains(stderr, "sbom.creator (BSI TR-03183-2 2.1.0 §5.2.1)") {
		t.Errorf("stderr lacks the sbom.creator line:\n%s", stderr)
	}
	c := d.Artifacts[0].Checks
	if c.Profile == nil || c.Profile.Name != profileName {
		t.Errorf("checks.profile = %+v", c.Profile)
	}
	if len(c.Failed) == 0 || c.Failed[0].Requirement != "sbom.creator" {
		t.Errorf("checks.failed = %+v, want sbom.creator first", c.Failed)
	}
	raw, err := os.ReadFile(filepath.Join(runDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx struct {
		Artifacts []struct {
			GateFindings []struct {
				SBOM bool `json:"sbom"`
			} `json:"gateFindings"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range idx.Artifacts[0].GateFindings {
		found = found || f.SBOM
	}
	if !found {
		t.Errorf("index.json has no sbom gate finding: %s", raw)
	}
}

func TestRootProfilePasses(t *testing.T) {
	code, d, _, stderr := profileRun(t, "bsi-pass.cdx.json", true)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	c := d.Artifacts[0].Checks
	if c.Gate != "pass" || c.Profile == nil || c.Profile.GuidelineVersion != "2.1.0" || c.Profile.Guideline != "BSI TR-03183-2" {
		t.Errorf("checks = %+v", c)
	}
	want := map[string]int{"full": 1, "logical": 1, "assembled": 1, "identified": 1, "referenced": 1}
	if diff := cmp.Diff(want, c.ProfileLevels); diff != "" {
		t.Errorf("profileLevels (-want +got):\n%s", diff)
	}
}

// Acceptance criterion 1: the failing fixture is a document today's default
// gate accepts.
func TestRootProfileFixtureDefaultGatePasses(t *testing.T) {
	code, d, _, stderr := profileRun(t, "bsi-fail.cdx.json", false)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if d.Artifacts[0].Checks.Profile != nil {
		t.Errorf("profile recorded without gate.profile")
	}
}
