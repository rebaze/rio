package gate_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/rebaze/rio/internal/gate"
	"github.com/rebaze/rio/internal/sbom"
)

const profileName = "bsi-tr-03183-2@2.1.0"

var sha512Hex = strings.Repeat("ab", 64)

func prop(name, value string) map[string]any { return map[string]any{"name": name, "value": value} }

func creatorEmail() map[string]any {
	return map[string]any{"name": "Example GmbH", "contact": []any{map[string]any{"email": "sbom@example.org"}}}
}

func concluded(expr string) []any {
	return []any{map[string]any{"expression": expr, "acknowledgement": "concluded"}}
}

func distribution(alg, content string) map[string]any {
	return map[string]any{
		"type":   "distribution",
		"url":    "https://downloads.example.org/cart-api-1.4.0.tar.gz",
		"hashes": []any{map[string]any{"alg": alg, "content": content}},
	}
}

// fullFields gives obj everything a fully described component needs beyond
// creator, name, version, dependencies and licences.
func fullFields(obj map[string]any, filename string) {
	props, _ := obj["properties"].([]any)
	var kept []any
	for _, p := range props {
		if p.(map[string]any)["name"] != "rio:tr-03183-2:level" {
			kept = append(kept, p)
		}
	}
	obj["properties"] = append(kept,
		prop("bsi:component:filename", filename),
		prop("bsi:component:executable", "non-executable"),
		prop("bsi:component:archive", "archive"),
		prop("bsi:component:structured", "structured"),
	)
	obj["externalReferences"] = []any{distribution("SHA-512", sha512Hex)}
}

// conforming is a document that meets the profile with one component at each
// level: a logical subject, a full file, an assembled library, an identified
// and a referenced component.
func conforming() map[string]any {
	file := map[string]any{
		"type": "file", "bom-ref": "file", "name": "cart-api-1.4.0.tar.gz", "version": "1.4.0",
		"manufacturer": creatorEmail(),
		"licenses":     []any{map[string]any{"license": map[string]any{"id": "Apache-2.0", "acknowledgement": "concluded"}}},
	}
	fullFields(file, "cart-api-1.4.0.tar.gz")
	return map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
		"metadata": map[string]any{
			"timestamp":    "2026-10-26T10:00:00Z",
			"manufacturer": creatorEmail(),
			"component": map[string]any{
				"type": "application", "bom-ref": "subject", "name": "cart-api", "version": "1.4.0",
				"manufacturer": map[string]any{"name": "Example GmbH", "url": []any{"https://example.org"}},
				"licenses":     concluded("Apache-2.0"),
				"properties":   []any{prop("rio:tr-03183-2:level", "logical")},
			},
		},
		"components": []any{
			file,
			map[string]any{
				"type": "library", "bom-ref": "lib", "name": "zlib", "version": "1.3.1",
				"manufacturer": creatorEmail(),
				"licenses":     concluded("Zlib"),
				"properties": []any{
					prop("rio:tr-03183-2:level", "assembled"),
					prop("bsi:component:executable", "non-executable"),
					prop("bsi:component:archive", "no archive"),
					prop("bsi:component:structured", "unstructured"),
				},
			},
			map[string]any{
				"type": "library", "bom-ref": "ident", "name": "openssl", "version": "3.0.13",
				"manufacturer": creatorEmail(),
				"properties":   []any{prop("rio:tr-03183-2:level", "identified")},
			},
			map[string]any{
				"type": "container", "bom-ref": "ref", "name": "base-image", "version": "1.0",
				"manufacturer":       creatorEmail(),
				"externalReferences": []any{map[string]any{"type": "bom", "url": "https://example.org/base.cdx.json"}},
			},
		},
		"dependencies": []any{
			map[string]any{"ref": "subject", "dependsOn": []any{"file", "lib", "ident", "ref"}},
			map[string]any{"ref": "file"},
			map[string]any{"ref": "lib"},
		},
		"compositions": []any{
			map[string]any{"aggregate": "complete", "dependencies": []any{"subject", "file"}},
			map[string]any{"aggregate": "incomplete", "assemblies": []any{"lib"}},
		},
	}
}

// at walks a decoded document: string keys index objects, ints index arrays.
func at(doc map[string]any, path ...any) map[string]any {
	var cur any = doc
	for _, p := range path {
		switch k := p.(type) {
		case string:
			cur = cur.(map[string]any)[k]
		case int:
			cur = cur.([]any)[k]
		}
	}
	return cur.(map[string]any)
}

func subjectOf(doc map[string]any) map[string]any { return at(doc, "metadata", "component") }

func component(doc map[string]any, i int) map[string]any { return at(doc, "components", i) }

// setProp replaces every property called name with value, or adds one.
func setProp(obj map[string]any, name, value string) {
	props, _ := obj["properties"].([]any)
	var kept []any
	for _, p := range props {
		if p.(map[string]any)["name"] != name {
			kept = append(kept, p)
		}
	}
	obj["properties"] = append(kept, prop(name, value))
}

func dropProp(obj map[string]any, name string) {
	props, _ := obj["properties"].([]any)
	var kept []any
	for _, p := range props {
		if p.(map[string]any)["name"] != name {
			kept = append(kept, p)
		}
	}
	obj["properties"] = kept
}

func loadMap(t *testing.T, doc map[string]any) *sbom.Document {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return load(t, string(data))
}

func profileCheck(t *testing.T, doc map[string]any, reqs gate.Requirements) gate.Result {
	t.Helper()
	reqs.Profile = profileName
	return gate.CheckRequirements(loadMap(t, doc), reqs)
}

// brief drops Details so a test can compare what index.json carries.
type brief struct {
	SBOM      bool
	Subject   bool
	Component string
	Missing   []string
}

func briefs(fs []gate.Finding) []brief {
	out := []brief{}
	for _, f := range fs {
		out = append(out, brief{SBOM: f.SBOM, Subject: f.Subject, Component: f.Component, Missing: f.Missing})
	}
	return out
}

func allLevels(full, logical, assembled, identified, referenced int) map[string]int {
	return map[string]int{"full": full, "logical": logical, "assembled": assembled, "identified": identified, "referenced": referenced}
}

func TestLookupProfile(t *testing.T) {
	p, ok := gate.LookupProfile(profileName)
	if !ok {
		t.Fatalf("LookupProfile(%q) not found", profileName)
	}
	want := gate.Profile{Name: profileName, Guideline: "BSI TR-03183-2", GuidelineVersion: "2.1.0"}
	if p != want {
		t.Errorf("LookupProfile = %+v, want %+v", p, want)
	}
	for _, name := range []string{"", "bsi-tr-03183-2", "bsi-tr-03183-2@2.0.0"} {
		if _, ok := gate.LookupProfile(name); ok {
			t.Errorf("LookupProfile(%q) found, want not found", name)
		}
	}
}

func TestProfileSection(t *testing.T) {
	cases := map[string]string{
		"sbom.specVersion":                "§4",
		"sbom.creator":                    "§5.2.1",
		"sbom.timestamp":                  "§5.2.1",
		"sbom.vulnerabilities":            "§3.1",
		"subject.distributionLicences":    "§5.2.2, §6.1",
		"components.distributionLicences": "§5.2.2, §6.1",
		"subject.creator":                 "§5.2.2",
		"subject.name":                    "§5.2.2",
		"subject.version":                 "§5.2.2",
		"subject.filename":                "§5.2.2",
		"subject.dependencies":            "§5.2.2",
		"subject.deployableHash":          "§5.2.2",
		"subject.executable":              "§5.2.2",
		"subject.archive":                 "§5.2.2",
		"subject.structured":              "§5.2.2",
		"components.name":                 "§5.2.2",
		"components.version":              "§5.2.2",
		"components.creator":              "§5.2.2",
		"components.filename":             "§5.2.2",
		"components.dependencies":         "§5.2.2",
		"components.deployableHash":       "§5.2.2",
		"components.executable":           "§5.2.2",
		"components.archive":              "§5.2.2",
		"components.structured":           "§5.2.2",
		"subject.level":                   "",
		"components.level":                "",
		"components.purl":                 "",
		"subject.securityContact":         "",
		"subject.digest":                  "",
		"sbom.name":                       "",
		"bogus":                           "",
	}
	for id, want := range cases {
		if got := gate.ProfileSection(id); got != want {
			t.Errorf("ProfileSection(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestProfileConformingPasses(t *testing.T) {
	got := profileCheck(t, conforming(), gate.Requirements{})
	if !got.OK() {
		t.Fatalf("OK() = false; findings: %+v", got.Findings)
	}
	if got.Profile == nil || got.Profile.Name != profileName || got.Profile.Guideline != "BSI TR-03183-2" || got.Profile.GuidelineVersion != "2.1.0" {
		t.Errorf("Profile = %+v", got.Profile)
	}
	if diff := cmp.Diff(allLevels(1, 1, 1, 1, 1), got.ProfileLevels); diff != "" {
		t.Errorf("ProfileLevels (-want +got):\n%s", diff)
	}
	if got.ComponentCount != 4 {
		t.Errorf("ComponentCount = %d, want 4", got.ComponentCount)
	}
}

func TestProfileEvaluations(t *testing.T) {
	doc := conforming()
	delete(component(doc, 2), "manufacturer") // identified: creator fails
	got := profileCheck(t, doc, gate.Requirements{Components: []gate.Requirement{gate.RequirePURL}, Subject: []gate.Requirement{gate.RequireDigest}})

	ev := func(scope, req string, evaluated, failed int) gate.Evaluation {
		outcome := "pass"
		if evaluated == 0 {
			outcome = "not-evaluated"
		} else if failed > 0 {
			outcome = "fail"
		}
		return gate.Evaluation{Scope: scope, Requirement: req, Evaluated: evaluated, Failed: failed, Outcome: outcome}
	}
	want := []gate.Evaluation{
		ev("sbom", "specVersion", 1, 0),
		ev("sbom", "creator", 1, 0),
		ev("sbom", "timestamp", 1, 0),
		ev("sbom", "vulnerabilities", 1, 0),
		ev("subject", "name", 1, 0),
		ev("subject", "version", 1, 0),
		ev("subject", "level", 1, 0),
		ev("subject", "creator", 1, 0),
		ev("subject", "filename", 0, 0),
		ev("subject", "dependencies", 1, 0),
		ev("subject", "distributionLicences", 1, 0),
		ev("subject", "deployableHash", 0, 0),
		ev("subject", "executable", 0, 0),
		ev("subject", "archive", 0, 0),
		ev("subject", "structured", 0, 0),
		ev("subject", "digest", 1, 1),
		ev("components", "name", 4, 0),
		ev("components", "version", 4, 0),
		ev("components", "purl", 4, 4),
		ev("components", "level", 4, 0),
		ev("components", "creator", 4, 1),
		ev("components", "filename", 1, 0),
		ev("components", "dependencies", 2, 0),
		ev("components", "distributionLicences", 2, 0),
		ev("components", "deployableHash", 1, 0),
		ev("components", "executable", 2, 0),
		ev("components", "archive", 2, 0),
		ev("components", "structured", 2, 0),
	}
	if diff := cmp.Diff(want, got.Evaluations); diff != "" {
		t.Errorf("Evaluations (-want +got):\n%s", diff)
	}
}

func TestProfileFieldFailures(t *testing.T) {
	const fileID = "cart-api-1.4.0.tar.gz@1.4.0"
	sbomScope := func(m string) []brief { return []brief{{SBOM: true, Missing: []string{m}}} }
	subjectScope := func(m string) []brief { return []brief{{Subject: true, Missing: []string{m}}} }
	compScope := func(id, m string) []brief { return []brief{{Component: id, Missing: []string{m}}} }
	// makeSubjectFull turns the logical subject into a fully described one
	// that passes, so a row can then break one full-only field.
	makeSubjectFull := func(doc map[string]any) { fullFields(subjectOf(doc), "cart-api") }

	cases := []struct {
		id     string
		reqs   gate.Requirements
		mutate func(doc map[string]any)
		want   []brief
	}{
		{"sbom.specVersion", gate.Requirements{}, func(d map[string]any) { d["specVersion"] = "1.5" }, sbomScope("specVersion")},
		{"sbom.creator", gate.Requirements{}, func(d map[string]any) { delete(at(d, "metadata"), "manufacturer") }, sbomScope("creator")},
		{"sbom.timestamp", gate.Requirements{}, func(d map[string]any) { at(d, "metadata")["timestamp"] = "2026-10-26 10:00" }, sbomScope("timestamp")},
		{"sbom.vulnerabilities", gate.Requirements{}, func(d map[string]any) {
			d["vulnerabilities"] = []any{map[string]any{"id": "CVE-2024-0001"}}
		}, sbomScope("vulnerabilities")},
		{"subject.level", gate.Requirements{}, func(d map[string]any) {
			makeSubjectFull(d)
			setProp(subjectOf(d), "rio:tr-03183-2:level", "full")
		}, subjectScope("level")},
		{"subject.creator", gate.Requirements{}, func(d map[string]any) {
			subjectOf(d)["manufacturer"] = map[string]any{"name": "Example GmbH", "url": []any{"example.org"}}
		}, subjectScope("creator")},
		{"subject.filename", gate.Requirements{}, func(d map[string]any) {
			makeSubjectFull(d)
			setProp(subjectOf(d), "bsi:component:filename", "  ")
		}, subjectScope("filename")},
		{"subject.dependencies", gate.Requirements{}, func(d map[string]any) {
			d["dependencies"] = d["dependencies"].([]any)[1:]
		}, subjectScope("dependencies")},
		{"subject.distributionLicences", gate.Requirements{}, func(d map[string]any) {
			subjectOf(d)["licenses"] = []any{map[string]any{"license": map[string]any{"name": "Apache License 2.0", "acknowledgement": "concluded"}}}
		}, subjectScope("distributionLicences")},
		{"subject.deployableHash", gate.Requirements{}, func(d map[string]any) {
			makeSubjectFull(d)
			subjectOf(d)["externalReferences"] = []any{distribution("SHA-512", sha512Hex[:127])}
		}, subjectScope("deployableHash")},
		{"subject.executable", gate.Requirements{}, func(d map[string]any) {
			makeSubjectFull(d)
			setProp(subjectOf(d), "bsi:component:executable", "yes")
		}, subjectScope("executable")},
		{"subject.archive", gate.Requirements{}, func(d map[string]any) {
			makeSubjectFull(d)
			dropProp(subjectOf(d), "bsi:component:archive")
		}, subjectScope("archive")},
		{"subject.structured", gate.Requirements{}, func(d map[string]any) {
			makeSubjectFull(d)
			s := subjectOf(d)
			s["properties"] = append(s["properties"].([]any), prop("bsi:component:structured", "structured"))
		}, subjectScope("structured")},
		{"subject.securityContact", gate.Requirements{Subject: []gate.Requirement{gate.RequireSecurityContact}}, func(map[string]any) {}, subjectScope("securityContact")},
		{"subject.digest", gate.Requirements{Subject: []gate.Requirement{gate.RequireDigest}}, func(map[string]any) {}, subjectScope("digest")},
		{"components.level", gate.Requirements{}, func(d map[string]any) {
			setProp(component(d, 0), "rio:tr-03183-2:level", "Logical")
		}, compScope(fileID, "level")},
		{"components.creator", gate.Requirements{}, func(d map[string]any) {
			component(d, 2)["manufacturer"] = map[string]any{"contact": []any{map[string]any{"email": "@example.org"}}}
		}, compScope("openssl@3.0.13", "creator")},
		{"components.filename", gate.Requirements{}, func(d map[string]any) {
			setProp(component(d, 0), "bsi:component:filename", `dist\cart-api-1.4.0.tar.gz`)
		}, compScope(fileID, "filename")},
		{"components.dependencies", gate.Requirements{}, func(d map[string]any) {
			at(d, "compositions", 1)["aggregate"] = "not_specified"
		}, compScope("zlib@1.3.1", "dependencies")},
		{"components.distributionLicences", gate.Requirements{}, func(d map[string]any) {
			at(d, "components", 0, "licenses", 0, "license")["acknowledgement"] = "declared"
		}, compScope(fileID, "distributionLicences")},
		{"components.deployableHash", gate.Requirements{}, func(d map[string]any) {
			component(d, 0)["externalReferences"] = []any{distribution("SHA-256", strings.Repeat("ab", 32))}
		}, compScope(fileID, "deployableHash")},
		{"components.executable", gate.Requirements{}, func(d map[string]any) {
			setProp(component(d, 1), "bsi:component:executable", "Executable")
		}, compScope("zlib@1.3.1", "executable")},
		{"components.archive", gate.Requirements{}, func(d map[string]any) {
			c := component(d, 0)
			c["properties"] = append(c["properties"].([]any), prop("bsi:component:archive", "archive"))
		}, compScope(fileID, "archive")},
		{"components.structured", gate.Requirements{}, func(d map[string]any) {
			dropProp(component(d, 1), "bsi:component:structured")
		}, compScope("zlib@1.3.1", "structured")},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			doc := conforming()
			tc.mutate(doc)
			got := profileCheck(t, doc, tc.reqs)
			if diff := cmp.Diff(tc.want, briefs(got.Findings)); diff != "" {
				t.Errorf("findings (-want +got):\n%s", diff)
			}
		})
	}
}

func TestProfileFailureOrder(t *testing.T) {
	doc := conforming()
	delete(doc, "compositions")
	delete(at(doc, "metadata"), "timestamp")
	doc["specVersion"] = "1.5"
	doc["vulnerabilities"] = []any{map[string]any{"id": "CVE-2024-0001"}}
	s := subjectOf(doc)
	delete(s, "manufacturer")
	delete(s, "version")
	delete(s, "properties") // full now
	f := component(doc, 0)
	delete(f, "name")
	delete(f, "properties")
	delete(f, "externalReferences")

	got := profileCheck(t, doc, gate.Requirements{Components: []gate.Requirement{gate.RequirePURL}, Subject: []gate.Requirement{gate.RequireDigest, gate.RequireSecurityContact}})
	want := []brief{
		{SBOM: true, Missing: []string{"specVersion", "timestamp", "vulnerabilities"}},
		{Subject: true, Missing: []string{"version", "creator", "filename", "dependencies", "deployableHash", "executable", "archive", "structured", "securityContact", "digest"}},
		{Component: "components[0]@1.4.0", Missing: []string{"name", "purl", "filename", "dependencies", "deployableHash", "executable", "archive", "structured"}},
		{Component: "zlib@1.3.1", Missing: []string{"purl", "dependencies"}},
		{Component: "openssl@3.0.13", Missing: []string{"purl"}},
		{Component: "base-image@1.0", Missing: []string{"purl"}},
	}
	if diff := cmp.Diff(want, briefs(got.Findings)); diff != "" {
		t.Errorf("findings (-want +got):\n%s", diff)
	}
}

func TestProfileLevelRelaxes(t *testing.T) {
	doc := conforming()
	// assembled without filename or hash: the conforming library already has
	// neither; give it a full component's leftovers removed explicitly.
	lib := component(doc, 1)
	dropProp(lib, "bsi:component:filename")
	delete(lib, "externalReferences")
	// logical without any BSI properties.
	comps := doc["components"].([]any)
	doc["components"] = append(comps,
		map[string]any{
			"type": "application", "bom-ref": "app", "name": "worker", "version": "2.0",
			"manufacturer": creatorEmail(), "licenses": concluded("MIT"),
			"properties": []any{prop("rio:tr-03183-2:level", "logical")},
		},
		map[string]any{
			"name": "libc", "version": "2.39", "manufacturer": creatorEmail(),
			"properties": []any{prop("rio:tr-03183-2:level", "identified")},
		},
	)
	doc["dependencies"] = append(doc["dependencies"].([]any), map[string]any{"ref": "app", "dependsOn": []any{}})
	at(doc, "compositions", 0)["dependencies"] = []any{"subject", "file", "app"}

	got := profileCheck(t, doc, gate.Requirements{})
	if !got.OK() {
		t.Fatalf("OK() = false; findings: %+v", briefs(got.Findings))
	}
	if diff := cmp.Diff(allLevels(1, 2, 1, 2, 1), got.ProfileLevels); diff != "" {
		t.Errorf("ProfileLevels (-want +got):\n%s", diff)
	}
}

func TestProfileBadLevel(t *testing.T) {
	fullMissing := []string{"level", "filename", "deployableHash", "executable", "archive", "structured"}
	for name, mutate := range map[string]func(obj map[string]any){
		"referenced is not a property value": func(obj map[string]any) { setProp(obj, "rio:tr-03183-2:level", "referenced") },
		"duplicated valid value": func(obj map[string]any) {
			obj["properties"] = append(obj["properties"].([]any), prop("rio:tr-03183-2:level", "identified"))
		},
		"non-string value": func(obj map[string]any) {
			dropProp(obj, "rio:tr-03183-2:level")
			obj["properties"] = append(obj["properties"].([]any), map[string]any{"name": "rio:tr-03183-2:level", "value": 3})
		},
	} {
		t.Run(name, func(t *testing.T) {
			doc := conforming()
			mutate(component(doc, 2)) // the identified openssl: no licences, no deps
			got := profileCheck(t, doc, gate.Requirements{})
			want := []brief{{Component: "openssl@3.0.13", Missing: []string{"level", "filename", "dependencies", "distributionLicences", "deployableHash", "executable", "archive", "structured"}}}
			if diff := cmp.Diff(want, briefs(got.Findings)); diff != "" {
				t.Errorf("findings (-want +got):\n%s", diff)
			}
			if len(got.Findings) == 1 && got.Findings[0].Details["level"] == "" {
				t.Error(`Details["level"] is empty; the message needs the offending value`)
			}
			if diff := cmp.Diff(allLevels(2, 1, 1, 0, 1), got.ProfileLevels); diff != "" {
				t.Errorf("ProfileLevels (-want +got):\n%s", diff)
			}
		})
	}

	// The subject, too.
	doc := conforming()
	setProp(subjectOf(doc), "rio:tr-03183-2:level", "referenced")
	got := profileCheck(t, doc, gate.Requirements{})
	if diff := cmp.Diff([]brief{{Subject: true, Missing: fullMissing}}, briefs(got.Findings)); diff != "" {
		t.Errorf("subject findings (-want +got):\n%s", diff)
	}
}

func TestProfileBOMReferenceWins(t *testing.T) {
	doc := conforming()
	// A referenced component's level property is ignored, even a bad one.
	setProp(component(doc, 3), "rio:tr-03183-2:level", "nonsense")
	got := profileCheck(t, doc, gate.Requirements{})
	if !got.OK() {
		t.Fatalf("OK() = false; findings: %+v", briefs(got.Findings))
	}
	if got.ProfileLevels["referenced"] != 1 {
		t.Errorf("ProfileLevels = %v, want referenced 1", got.ProfileLevels)
	}
}

// A bom reference counts only when its url identifies another BOM; a blank
// url leaves the component checked, and reported, as full.
func TestProfileBlankBOMReferenceIsFull(t *testing.T) {
	for name, url := range map[string]any{"empty": "", "whitespace": "  \t", "absent": nil, "not a string": 7} {
		t.Run(name, func(t *testing.T) {
			doc := conforming()
			ref := map[string]any{"type": "bom"}
			if url != nil {
				ref["url"] = url
			}
			component(doc, 3)["externalReferences"] = []any{ref}
			got := profileCheck(t, doc, gate.Requirements{})
			if got.ProfileLevels["referenced"] != 0 || got.ProfileLevels["full"] != 2 {
				t.Errorf("ProfileLevels = %v, want base-image counted as full", got.ProfileLevels)
			}
			want := []brief{{Component: "base-image@1.0", Missing: []string{"filename", "dependencies", "distributionLicences", "deployableHash", "executable", "archive", "structured"}}}
			if diff := cmp.Diff(want, briefs(got.Findings)); diff != "" {
				t.Errorf("findings (-want +got):\n%s", diff)
			}
		})
	}
}

func TestProfileMalformedShapes(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(doc map[string]any)
		want   []brief
	}{
		{"component without bom-ref", func(d map[string]any) { delete(component(d, 1), "bom-ref") },
			[]brief{{Component: "zlib@1.3.1", Missing: []string{"dependencies"}}}},
		{"bom-ref not a string", func(d map[string]any) { component(d, 1)["bom-ref"] = 7 },
			[]brief{{Component: "zlib@1.3.1", Missing: []string{"dependencies"}}}},
		{"no dependencies or compositions", func(d map[string]any) { delete(d, "dependencies"); delete(d, "compositions") },
			[]brief{
				{Subject: true, Missing: []string{"dependencies"}},
				{Component: "cart-api-1.4.0.tar.gz@1.4.0", Missing: []string{"dependencies"}},
				{Component: "zlib@1.3.1", Missing: []string{"dependencies"}},
			}},
		{"dependencies and compositions not arrays", func(d map[string]any) { d["dependencies"] = "x"; d["compositions"] = map[string]any{} },
			[]brief{
				{Subject: true, Missing: []string{"dependencies"}},
				{Component: "cart-api-1.4.0.tar.gz@1.4.0", Missing: []string{"dependencies"}},
				{Component: "zlib@1.3.1", Missing: []string{"dependencies"}},
			}},
		{"manufacturer as a string", func(d map[string]any) {
			at(d, "metadata")["manufacturer"] = "Example GmbH"
			component(d, 3)["manufacturer"] = "Example GmbH"
		}, []brief{{SBOM: true, Missing: []string{"creator"}}, {Component: "base-image@1.0", Missing: []string{"creator"}}}},
		{"contact and url wrong shapes", func(d map[string]any) {
			at(d, "metadata")["manufacturer"] = map[string]any{"contact": "sbom@example.org", "url": "https://example.org"}
			component(d, 3)["manufacturer"] = map[string]any{"contact": []any{"sbom@example.org", map[string]any{"email": 5}}, "url": []any{3, "ftp://example.org", "https://"}}
		}, []brief{{SBOM: true, Missing: []string{"creator"}}, {Component: "base-image@1.0", Missing: []string{"creator"}}}},
		{"creator url without a host name", func(d map[string]any) {
			at(d, "metadata")["manufacturer"] = map[string]any{"url": []any{"https://:443", "http://:80/path"}}
			component(d, 3)["manufacturer"] = map[string]any{"url": []any{"https://:443"}}
		}, []brief{{SBOM: true, Missing: []string{"creator"}}, {Component: "base-image@1.0", Missing: []string{"creator"}}}},
		{"properties not an array", func(d map[string]any) { component(d, 0)["properties"] = map[string]any{"bsi:component:filename": "x"} },
			[]brief{{Component: "cart-api-1.4.0.tar.gz@1.4.0", Missing: []string{"filename", "executable", "archive", "structured"}}}},
		{"property entries not objects", func(d map[string]any) {
			component(d, 2)["properties"] = []any{"rio:tr-03183-2:level", 4, nil}
		}, []brief{{Component: "openssl@3.0.13", Missing: []string{"filename", "dependencies", "distributionLicences", "deployableHash", "executable", "archive", "structured"}}}},
		{"hashes entries not objects", func(d map[string]any) {
			component(d, 0)["externalReferences"] = []any{map[string]any{"type": "distribution", "hashes": []any{sha512Hex, nil}}, "distribution"}
		}, []brief{{Component: "cart-api-1.4.0.tar.gz@1.4.0", Missing: []string{"deployableHash"}}}},
		{"licenses wrong shapes", func(d map[string]any) {
			subjectOf(d)["licenses"] = []any{"Apache-2.0", map[string]any{"license": "Apache-2.0"}, map[string]any{"expression": 5, "acknowledgement": "concluded"}}
			component(d, 1)["licenses"] = "Zlib"
		}, []brief{{Subject: true, Missing: []string{"distributionLicences"}}, {Component: "zlib@1.3.1", Missing: []string{"distributionLicences"}}}},
		{"metadata absent", func(d map[string]any) { delete(d, "metadata") },
			[]brief{{SBOM: true, Missing: []string{"creator", "timestamp"}}, {Subject: true, Missing: []string{"name", "version"}}}},
		{"metadata not an object", func(d map[string]any) { d["metadata"] = []any{} },
			[]brief{{SBOM: true, Missing: []string{"creator", "timestamp"}}, {Subject: true, Missing: []string{"name", "version"}}}},
		{"timestamp not a string", func(d map[string]any) { at(d, "metadata")["timestamp"] = 1730000000 },
			[]brief{{SBOM: true, Missing: []string{"timestamp"}}}},
		{"component entry not an object", func(d map[string]any) { d["components"] = append(d["components"].([]any), 42) },
			[]brief{{Component: "components[4]", Missing: []string{"name", "version", "creator", "filename", "dependencies", "distributionLicences", "deployableHash", "executable", "archive", "structured"}}}},
		{"components not an array", func(d map[string]any) { d["components"] = map[string]any{} },
			[]brief{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := conforming()
			tc.mutate(doc)
			got := profileCheck(t, doc, gate.Requirements{})
			if diff := cmp.Diff(tc.want, briefs(got.Findings)); diff != "" {
				t.Errorf("findings (-want +got):\n%s", diff)
			}
		})
	}
}

func TestProfileAbsentSubjectNotCounted(t *testing.T) {
	doc := conforming()
	delete(at(doc, "metadata"), "component")
	got := profileCheck(t, doc, gate.Requirements{})
	if diff := cmp.Diff(allLevels(1, 0, 1, 1, 1), got.ProfileLevels); diff != "" {
		t.Errorf("ProfileLevels (-want +got):\n%s", diff)
	}
	want := []brief{{Subject: true, Missing: []string{"name", "version"}}}
	if diff := cmp.Diff(want, briefs(got.Findings)); diff != "" {
		t.Errorf("findings (-want +got):\n%s", diff)
	}
}

func TestProfileRequireAdds(t *testing.T) {
	doc := conforming()
	delete(component(doc, 2), "manufacturer")
	delete(component(doc, 3), "name")
	component(doc, 1)["purl"] = "pkg:generic/zlib@1.3.1"
	got := profileCheck(t, doc, gate.Requirements{Components: []gate.Requirement{gate.RequireName, gate.RequireVersion, gate.RequirePURL}})
	want := []brief{
		{Component: "cart-api-1.4.0.tar.gz@1.4.0", Missing: []string{"purl"}},
		{Component: "openssl@3.0.13", Missing: []string{"purl", "creator"}},
		{Component: "components[3]@1.0", Missing: []string{"name", "purl"}},
	}
	if diff := cmp.Diff(want, briefs(got.Findings)); diff != "" {
		t.Errorf("findings (-want +got):\n%s", diff)
	}
}

func TestProfileUnknownIsNoProfile(t *testing.T) {
	doc := conforming()
	without := gate.CheckRequirements(loadMap(t, doc), gate.Requirements{Components: all()})
	with := gate.CheckRequirements(loadMap(t, doc), gate.Requirements{Components: all(), Profile: "bsi-tr-03183-2@2.0.0"})
	if diff := cmp.Diff(without, with); diff != "" {
		t.Errorf("unknown profile changed the result (-none +unknown):\n%s", diff)
	}
	if with.Profile != nil || with.ProfileLevels != nil {
		t.Errorf("Profile = %+v, ProfileLevels = %v; want nil for an unknown profile", with.Profile, with.ProfileLevels)
	}
}

func TestProfileDoesNotModifyDocument(t *testing.T) {
	doc := conforming()
	data, _ := json.Marshal(doc)
	d := load(t, string(data))
	before, _ := d.Bytes()
	gate.CheckRequirements(d, gate.Requirements{Profile: profileName, Components: all(), Subject: []gate.Requirement{gate.RequireDigest}})
	after, _ := d.Bytes()
	if string(before) != string(after) {
		t.Error("the profile check modified the document")
	}
}

func TestProfileLicenceForms(t *testing.T) {
	cases := []struct {
		name     string
		licenses []any
		ok       bool
	}{
		{"concluded expression", concluded("MIT OR Apache-2.0"), true},
		{"concluded LicenseRef expression", concluded("LicenseRef-acme-eula"), true},
		{"concluded license id", []any{map[string]any{"license": map[string]any{"id": "MIT", "acknowledgement": "concluded"}}}, true},
		{"declared expression", []any{map[string]any{"expression": "MIT", "acknowledgement": "declared"}}, false},
		{"expression without acknowledgement", []any{map[string]any{"expression": "MIT"}}, false},
		{"malformed concluded expression", concluded("MIT AND"), false},
		{"unknown concluded expression", concluded("NotALicence-1.0"), false},
		{"unknown concluded id", []any{map[string]any{"license": map[string]any{"id": "NotALicence-1.0", "acknowledgement": "concluded"}}}, false},
		{"entry-level acknowledgement on a license", []any{map[string]any{"license": map[string]any{"id": "MIT"}, "acknowledgement": "concluded"}}, false},
		{"text only", []any{map[string]any{"license": map[string]any{"text": map[string]any{"content": "MIT License ..."}, "acknowledgement": "concluded"}}}, false},
		{"one good entry among bad", append(concluded("MIT AND"), concluded("MIT")...), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := conforming()
			subjectOf(doc)["licenses"] = tc.licenses
			got := profileCheck(t, doc, gate.Requirements{})
			if got.OK() != tc.ok {
				t.Errorf("OK() = %v, want %v; findings: %+v", got.OK(), tc.ok, briefs(got.Findings))
			}
		})
	}
}

// subjectNested is conforming with its full file component nested under the
// subject (metadata.component.components), where rio writes the TR file
// components from the build context.
func subjectNested() map[string]any {
	doc := conforming()
	list := doc["components"].([]any)
	subjectOf(doc)["components"] = []any{list[0]}
	doc["components"] = list[1:]
	return doc
}

func TestProfileChecksSubjectNestedComponents(t *testing.T) {
	got := profileCheck(t, subjectNested(), gate.Requirements{})
	if !got.OK() {
		t.Fatalf("OK() = false; findings: %+v", got.Findings)
	}
	if diff := cmp.Diff(allLevels(1, 1, 1, 1, 1), got.ProfileLevels); diff != "" {
		t.Errorf("ProfileLevels (-want +got):\n%s", diff)
	}
	if got.ComponentCount != 4 {
		t.Errorf("ComponentCount = %d, want 4 (3 in components, 1 under the subject)", got.ComponentCount)
	}

	doc := subjectNested()
	file := at(doc, "metadata", "component", "components", 0)
	var kept []any
	for _, p := range file["properties"].([]any) {
		if p.(map[string]any)["name"] != "bsi:component:filename" {
			kept = append(kept, p)
		}
	}
	file["properties"] = kept
	got = profileCheck(t, doc, gate.Requirements{})
	want := []brief{{Component: "cart-api-1.4.0.tar.gz@1.4.0", Missing: []string{"filename"}}}
	if diff := cmp.Diff(want, briefs(got.Findings)); diff != "" {
		t.Errorf("findings (-want +got):\n%s", diff)
	}
	for _, e := range got.Evaluations {
		if e.Scope == "components" && e.Requirement == "filename" && (e.Evaluated != 1 || e.Failed != 1) {
			t.Errorf("components.filename evaluation = %+v, want 1 evaluated, 1 failed", e)
		}
	}
}

// Without a profile the gate is exactly as before: subject-nested components
// are not in its inventory.
func TestDefaultGateIgnoresSubjectNestedComponents(t *testing.T) {
	got := gate.CheckRequirements(loadMap(t, subjectNested()), gate.Requirements{Components: []gate.Requirement{gate.RequireName, gate.RequireVersion, gate.RequirePURL}})
	if got.ComponentCount != 3 {
		t.Errorf("ComponentCount = %d, want 3", got.ComponentCount)
	}
	for _, f := range got.Findings {
		if strings.Contains(f.Component, "cart-api-1.4.0.tar.gz") {
			t.Errorf("default gate checked a subject-nested component: %+v", f)
		}
	}
}

func TestProfileSpecVersionForms(t *testing.T) {
	for _, tc := range []struct {
		version string
		pass    bool
	}{
		{"1.6", true}, {"1.7", true}, {"2.0", true},
		{"1.5", false}, {"1.x", false}, {"banana", false}, {"1..6", false},
	} {
		doc := conforming()
		doc["specVersion"] = tc.version
		res := profileCheck(t, doc, gate.Requirements{})
		failed := false
		for _, f := range res.Findings {
			if f.SBOM && len(f.Missing) > 0 && f.Missing[0] == "specVersion" {
				failed = true
				if f.Details["specVersion"] != tc.version {
					t.Errorf("%q: Details[specVersion] = %q", tc.version, f.Details["specVersion"])
				}
			}
		}
		if failed == tc.pass {
			t.Errorf("specVersion %q: failed = %v, want pass = %v", tc.version, failed, tc.pass)
		}
	}
}
