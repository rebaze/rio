package index

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rebaze/rio/internal/gate"
	"github.com/rebaze/rio/internal/sbom"
)

// profileChecks is what a profile run reports for a logical subject over a
// full, an assembled and an identified component, written out by hand so the
// test does not borrow the shape it checks from the gate.
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
		ComponentRequirements: []string{}, ComponentEvaluation: "evaluated",
		Evaluations: []gate.Evaluation{
			ev("sbom", "specVersion", 1), ev("sbom", "creator", 1), ev("sbom", "timestamp", 1), ev("sbom", "vulnerabilities", 1),
			ev("subject", "name", 1), ev("subject", "version", 1),
			ev("subject", "level", 1), ev("subject", "creator", 1), ev("subject", "filename", 0), ev("subject", "dependencies", 1),
			ev("subject", "distributionLicences", 1), ev("subject", "deployableHash", 0), ev("subject", "executable", 0),
			ev("subject", "archive", 0), ev("subject", "structured", 0),
			ev("components", "name", 3), ev("components", "version", 3),
			ev("components", "level", 3), ev("components", "creator", 3), ev("components", "filename", 1), ev("components", "dependencies", 2),
			ev("components", "distributionLicences", 2), ev("components", "deployableHash", 1), ev("components", "executable", 2),
			ev("components", "archive", 2), ev("components", "structured", 2),
		},
		SchemaValidation: "not-available", GraphCheck: "dangling-dependency-references",
		Profile:       &ProfileRef{Name: "bsi-tr-03183-2@2.1.0", Guideline: "BSI TR-03183-2", GuidelineVersion: "2.1.0"},
		ProfileLevels: map[string]int{"full": 1, "logical": 1, "assembled": 1, "identified": 1, "referenced": 0},
	}
	return c, Artifact{ID: "app", Components: 3, Gate: GateOK}
}

// evaluation returns a pointer to the scope/requirement entry of c.
func evaluation(t *testing.T, c *EffectiveChecks, scope, req string) *gate.Evaluation {
	t.Helper()
	for i := range c.Evaluations {
		if e := &c.Evaluations[i]; e.Scope == scope && e.Requirement == req {
			return e
		}
	}
	t.Fatalf("no %s.%s evaluation", scope, req)
	return nil
}

func without(c *EffectiveChecks, scope, req string) {
	var kept []gate.Evaluation
	for _, e := range c.Evaluations {
		if e.Scope != scope || e.Requirement != req {
			kept = append(kept, e)
		}
	}
	c.Evaluations = kept
}

func TestEffectiveChecksProfileValid(t *testing.T) {
	c, a := profileChecks()
	if err := c.Validate(a); err != nil {
		t.Fatalf("valid profile checks refused: %v", err)
	}
	// A failing sbom finding is explained by an sbom evaluation.
	c, a = profileChecks()
	a.Gate = GateFail
	a.GateFindings = []GateFinding{{SBOM: true, Missing: []string{"creator"}}}
	e := evaluation(t, &c, "sbom", "creator")
	e.Failed, e.Outcome = 1, "fail"
	if err := c.Validate(a); err != nil {
		t.Fatalf("sbom finding refused: %v", err)
	}
	// A subject that is not an object is not counted at any level, and
	// none of its profile fields is evaluated.
	c, a = profileChecks()
	c.ProfileLevels["logical"] = 0
	for _, r := range []string{"level", "creator", "dependencies", "distributionLicences"} {
		e := evaluation(t, &c, "subject", r)
		e.Evaluated, e.Outcome = 0, "not-evaluated"
	}
	if err := c.Validate(a); err != nil {
		t.Fatalf("absent subject refused: %v", err)
	}
}

func TestEffectiveChecksProfileInvalid(t *testing.T) {
	cases := map[string]func(*testing.T, *EffectiveChecks, *Artifact){
		"unknown name":      func(_ *testing.T, c *EffectiveChecks, _ *Artifact) { c.Profile.Name = "other@1" },
		"wrong guideline":   func(_ *testing.T, c *EffectiveChecks, _ *Artifact) { c.Profile.GuidelineVersion = "2.0.0" },
		"missing level key": func(_ *testing.T, c *EffectiveChecks, _ *Artifact) { delete(c.ProfileLevels, "referenced") },
		"extra level key":   func(_ *testing.T, c *EffectiveChecks, _ *Artifact) { c.ProfileLevels["other"] = 0 },
		"negative level": func(_ *testing.T, c *EffectiveChecks, _ *Artifact) {
			c.ProfileLevels["full"], c.ProfileLevels["logical"] = -1, 3
		},
		"wrong sum":          func(_ *testing.T, c *EffectiveChecks, _ *Artifact) { c.ProfileLevels["full"] = 5 },
		"levels w/o profile": func(_ *testing.T, c *EffectiveChecks, _ *Artifact) { c.Profile = nil },
		"sbom count not one": func(t *testing.T, c *EffectiveChecks, _ *Artifact) {
			evaluation(t, c, "sbom", "specVersion").Evaluated = 2
		},
		"unknown requirement": func(t *testing.T, c *EffectiveChecks, _ *Artifact) {
			evaluation(t, c, "sbom", "specVersion").Requirement = "bogus"
		},
		"component overcount": func(t *testing.T, c *EffectiveChecks, _ *Artifact) {
			evaluation(t, c, "components", "name").Evaluated = 4
		},
		"sbom without profile": func(_ *testing.T, c *EffectiveChecks, _ *Artifact) {
			c.Profile, c.ProfileLevels = nil, nil
		},
		"no evaluations":             func(_ *testing.T, c *EffectiveChecks, _ *Artifact) { c.Evaluations = []gate.Evaluation{} },
		"sbom entry removed":         func(_ *testing.T, c *EffectiveChecks, _ *Artifact) { without(c, "sbom", "timestamp") },
		"subject entry removed":      func(_ *testing.T, c *EffectiveChecks, _ *Artifact) { without(c, "subject", "filename") },
		"component entry removed":    func(_ *testing.T, c *EffectiveChecks, _ *Artifact) { without(c, "components", "deployableHash") },
		"only the sbom entries kept": func(_ *testing.T, c *EffectiveChecks, _ *Artifact) { c.Evaluations = c.Evaluations[:4] },
		"entries reordered": func(_ *testing.T, c *EffectiveChecks, _ *Artifact) {
			c.Evaluations[0], c.Evaluations[1] = c.Evaluations[1], c.Evaluations[0]
		},
		"mandatory component entry not evaluated": func(t *testing.T, c *EffectiveChecks, _ *Artifact) {
			e := evaluation(t, c, "components", "creator")
			e.Evaluated, e.Outcome = 0, "not-evaluated"
		},
		"component level not evaluated": func(t *testing.T, c *EffectiveChecks, _ *Artifact) {
			e := evaluation(t, c, "components", "level")
			e.Evaluated, e.Outcome = 0, "not-evaluated"
		},
		"component name undercount": func(t *testing.T, c *EffectiveChecks, _ *Artifact) {
			evaluation(t, c, "components", "name").Evaluated = 2
		},
		"filename count above full": func(t *testing.T, c *EffectiveChecks, _ *Artifact) {
			evaluation(t, c, "components", "filename").Evaluated = 2
		},
		"filename count below full": func(t *testing.T, c *EffectiveChecks, _ *Artifact) {
			e := evaluation(t, c, "components", "filename")
			e.Evaluated, e.Outcome = 0, "not-evaluated"
		},
		"executable count ignores assembled": func(t *testing.T, c *EffectiveChecks, _ *Artifact) {
			evaluation(t, c, "components", "executable").Evaluated = 1
		},
		"licences count includes identified": func(t *testing.T, c *EffectiveChecks, _ *Artifact) {
			evaluation(t, c, "components", "distributionLicences").Evaluated = 3
		},
		"subject counts disagree with its level": func(t *testing.T, c *EffectiveChecks, _ *Artifact) {
			e := evaluation(t, c, "subject", "filename")
			e.Evaluated, e.Outcome = 1, "pass"
		},
		"subject level without its subject": func(t *testing.T, c *EffectiveChecks, _ *Artifact) {
			e := evaluation(t, c, "subject", "level")
			e.Evaluated, e.Outcome = 0, "not-evaluated"
		},
		"subject logical but no logical level": func(_ *testing.T, c *EffectiveChecks, _ *Artifact) {
			c.ProfileLevels["logical"], c.ProfileLevels["full"] = 0, 2
		},
		"purl selected but not evaluated": func(_ *testing.T, c *EffectiveChecks, _ *Artifact) {
			c.ComponentRequirements = []string{"purl"}
		},
		"purl evaluated but not selected": func(_ *testing.T, c *EffectiveChecks, _ *Artifact) {
			evs := append([]gate.Evaluation{}, c.Evaluations[:17]...)
			evs = append(evs, gate.Evaluation{Scope: "components", Requirement: "purl", Evaluated: 3, Outcome: "pass"})
			c.Evaluations = append(evs, c.Evaluations[17:]...)
		},
		"subject opt-in not evaluated": func(_ *testing.T, c *EffectiveChecks, _ *Artifact) {
			c.SubjectRequirements = []string{"name", "version", "digest"}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c, a := profileChecks()
			change(t, &c, &a)
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

// profiledArtifact runs the gate profile over a testdata/profile fixture and
// records the result as normalization does.
func profiledArtifact(t *testing.T, fixture string, reqs gate.Requirements) (EffectiveChecks, Artifact) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "profile", fixture))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := sbom.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	reqs.Profile = gate.ProfileBSITR031832v210
	r := gate.CheckRequirements(doc, reqs)
	a := Artifact{ID: "cart-api", Components: r.ComponentCount, Gate: GateOK}
	for _, f := range r.Findings {
		a.GateFindings = append(a.GateFindings, GateFinding{SBOM: f.SBOM, Subject: f.Subject, Component: f.Component, Missing: f.Missing})
	}
	if len(a.GateFindings) > 0 {
		a.Gate = GateFail
	}
	c := EffectiveChecks{
		Version: 1, Mode: "warn", ComponentScope: "all components including nested", ComponentCount: r.ComponentCount,
		ComponentRequirements: []string{}, ComponentEvaluation: "evaluated", Evaluations: r.Evaluations,
		SchemaValidation: "not-available", GraphCheck: "dangling-dependency-references",
		Profile:       &ProfileRef{Name: r.Profile.Name, Guideline: r.Profile.Guideline, GuidelineVersion: r.Profile.GuidelineVersion},
		ProfileLevels: r.ProfileLevels,
	}
	if r.ComponentCount == 0 {
		c.ComponentEvaluation = "not-evaluated"
	}
	for _, req := range reqs.Components {
		c.ComponentRequirements = append(c.ComponentRequirements, string(req))
	}
	if len(reqs.Subject) > 0 {
		c.SubjectRequirements = []string{"name", "version"}
		for _, req := range reqs.Subject {
			c.SubjectRequirements = append(c.SubjectRequirements, string(req))
		}
	}
	return c, a
}

func TestEffectiveChecksProfiledRunAccepted(t *testing.T) {
	optIns := map[string]gate.Requirements{
		"profile only":         {},
		"name and version":     {Components: []gate.Requirement{gate.RequireName, gate.RequireVersion}},
		"purl and subject":     {Components: []gate.Requirement{gate.RequirePURL}, Subject: []gate.Requirement{gate.RequireDigest, gate.RequireSecurityContact}},
		"subject opt-ins only": {Subject: []gate.Requirement{gate.RequireSecurityContact}},
	}
	for _, fixture := range []string{"bsi-pass.cdx.json", "bsi-fail.cdx.json"} {
		for name, reqs := range optIns {
			t.Run(fixture+"/"+name, func(t *testing.T) {
				c, a := profiledArtifact(t, fixture, reqs)
				if err := c.Validate(a); err != nil {
					t.Fatalf("a real profiled run refused: %v\nevaluations: %+v\nlevels: %v", err, c.Evaluations, c.ProfileLevels)
				}
				// Dropping any one entry the run reported is refused.
				for i := range c.Evaluations {
					d := c
					d.Evaluations = append(append([]gate.Evaluation{}, c.Evaluations[:i]...), c.Evaluations[i+1:]...)
					if err := d.Validate(a); err == nil {
						t.Errorf("dropping %s.%s accepted", c.Evaluations[i].Scope, c.Evaluations[i].Requirement)
					}
				}
			})
		}
	}
}
