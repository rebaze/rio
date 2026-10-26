package index

import (
	"testing"

	"github.com/rebaze/rio/internal/gate"
)

func profileChecks() (EffectiveChecks, Artifact) {
	ev := func(scope, req string, evaluated int) gate.Evaluation {
		outcome := "pass"
		if evaluated == 0 {
			outcome = "not-evaluated"
		}
		return gate.Evaluation{Scope: scope, Requirement: req, Evaluated: evaluated, Outcome: outcome}
	}
	c := EffectiveChecks{
		Version: 1, Mode: "warn", ComponentScope: "all components including nested", ComponentCount: 3,
		ComponentRequirements: []string{"name", "version"}, ComponentEvaluation: "evaluated",
		Evaluations: []gate.Evaluation{
			ev("sbom", "specVersion", 1), ev("sbom", "creator", 1),
			ev("subject", "name", 1), ev("subject", "version", 1), ev("subject", "level", 1), ev("subject", "executable", 0),
			ev("components", "name", 3), ev("components", "version", 3), ev("components", "level", 2), ev("components", "filename", 0),
		},
		SchemaValidation: "not-available", GraphCheck: "dangling-dependency-references",
		Profile:       &ProfileRef{Name: "bsi-tr-03183-2@2.1.0", Guideline: "BSI TR-03183-2", GuidelineVersion: "2.1.0"},
		ProfileLevels: map[string]int{"full": 1, "logical": 1, "assembled": 0, "identified": 1, "referenced": 0},
	}
	return c, Artifact{ID: "app", Components: 3, Gate: GateOK}
}

func TestEffectiveChecksProfileValid(t *testing.T) {
	c, a := profileChecks()
	if err := c.Validate(a); err != nil {
		t.Fatalf("valid profile checks refused: %v", err)
	}
	// The subject adds one to the level total.
	c.ProfileLevels["full"] = 2
	if err := c.Validate(a); err != nil {
		t.Fatalf("subject-inclusive levels refused: %v", err)
	}
	// A failing sbom finding is explained by an sbom evaluation.
	c, a = profileChecks()
	a.Gate = GateFail
	a.GateFindings = []GateFinding{{SBOM: true, Missing: []string{"creator"}}}
	c.Evaluations[1].Failed, c.Evaluations[1].Outcome = 1, "fail"
	if err := c.Validate(a); err != nil {
		t.Fatalf("sbom finding refused: %v", err)
	}
}

func TestEffectiveChecksProfileInvalid(t *testing.T) {
	cases := map[string]func(*EffectiveChecks, *Artifact){
		"unknown name":        func(c *EffectiveChecks, _ *Artifact) { c.Profile.Name = "other@1" },
		"wrong guideline":     func(c *EffectiveChecks, _ *Artifact) { c.Profile.GuidelineVersion = "2.0.0" },
		"missing level key":   func(c *EffectiveChecks, _ *Artifact) { delete(c.ProfileLevels, "referenced") },
		"extra level key":     func(c *EffectiveChecks, _ *Artifact) { c.ProfileLevels["other"] = 0 },
		"negative level":      func(c *EffectiveChecks, _ *Artifact) { c.ProfileLevels["full"], c.ProfileLevels["logical"] = -1, 3 },
		"wrong sum":           func(c *EffectiveChecks, _ *Artifact) { c.ProfileLevels["full"] = 5 },
		"levels w/o profile":  func(c *EffectiveChecks, _ *Artifact) { c.Profile = nil },
		"sbom count not one":  func(c *EffectiveChecks, _ *Artifact) { c.Evaluations[0].Evaluated = 2 },
		"unknown requirement": func(c *EffectiveChecks, _ *Artifact) { c.Evaluations[0].Requirement = "bogus" },
		"component overcount": func(c *EffectiveChecks, _ *Artifact) { c.Evaluations[6].Evaluated = 4 },
		"sbom without profile": func(c *EffectiveChecks, _ *Artifact) {
			c.Profile, c.ProfileLevels = nil, nil
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c, a := profileChecks()
			change(&c, &a)
			if err := c.Validate(a); err == nil {
				t.Fatal("invalid profile checks accepted")
			}
		})
	}
}

func TestEffectiveChecksProfileFindings(t *testing.T) {
	cases := map[string]GateFinding{
		"unknown missing entry":   {Missing: []string{"bogus"}},
		"unevaluated missing":     {Subject: true, Missing: []string{"digest"}},
		"sbom and subject both":   {SBOM: true, Subject: true, Missing: []string{"creator"}},
		"wrong scope requirement": {SBOM: true, Missing: []string{"level"}},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			c, a := profileChecks()
			a.Gate, a.GateFindings = GateFail, []GateFinding{f}
			if err := c.Validate(a); err == nil {
				t.Fatal("invalid profile finding accepted")
			}
		})
	}
}

func TestEffectiveChecksSBOMFindingNeedsProfile(t *testing.T) {
	c := EffectiveChecks{
		Version: 1, Mode: "warn", ComponentScope: "all components including nested", ComponentCount: 1,
		ComponentRequirements: []string{"name"}, ComponentEvaluation: "evaluated",
		Evaluations: []gate.Evaluation{
			{Scope: "subject", Requirement: "name", Evaluated: 1, Outcome: "pass"},
			{Scope: "subject", Requirement: "version", Evaluated: 1, Outcome: "pass"},
			{Scope: "components", Requirement: "name", Evaluated: 1, Outcome: "pass"},
		},
		SchemaValidation: "not-available", GraphCheck: "dangling-dependency-references",
	}
	a := Artifact{ID: "app", Components: 1, Gate: GateOK}
	if err := c.Validate(a); err != nil {
		t.Fatalf("baseline refused: %v", err)
	}
	a.Gate, a.GateFindings = GateFail, []GateFinding{{SBOM: true, Missing: []string{"creator"}}}
	if err := c.Validate(a); err == nil {
		t.Fatal("sbom finding accepted without a profile")
	}
}
