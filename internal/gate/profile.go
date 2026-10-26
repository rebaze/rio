package gate

import (
	"fmt"
	"strings"

	"github.com/rebaze/rio/internal/sbom"
)

// Requirement names a requirement profile adds. They are the IDs' last part:
// "components.filename" is RequireFilename in the components scope.
const (
	// RequireLevel demands that a rio:tr-03183-2:level property, when
	// present, appears once with a known value.
	RequireLevel Requirement = "level"
	// RequireCreator demands a manufacturer with a contact email or an
	// absolute http(s) URL. In the sbom scope it is metadata.manufacturer.
	RequireCreator Requirement = "creator"
	// RequireFilename demands one nonblank bsi:component:filename property
	// that is a file name, not a path.
	RequireFilename Requirement = "filename"
	// RequireDependencies demands the component's own dependencies entry and
	// a composition that covers it.
	RequireDependencies Requirement = "dependencies"
	// RequireDistributionLicences demands a concluded licence in SPDX form.
	RequireDistributionLicences Requirement = "distributionLicences"
	// RequireDeployableHash demands a SHA-512 hash on a distribution
	// reference.
	RequireDeployableHash Requirement = "deployableHash"
	// RequireExecutable demands one bsi:component:executable property.
	RequireExecutable Requirement = "executable"
	// RequireArchive demands one bsi:component:archive property.
	RequireArchive Requirement = "archive"
	// RequireStructured demands one bsi:component:structured property.
	RequireStructured Requirement = "structured"

	// RequireSpecVersion demands CycloneDX 1.6 or higher.
	RequireSpecVersion Requirement = "specVersion"
	// RequireTimestamp demands an RFC 3339 metadata.timestamp.
	RequireTimestamp Requirement = "timestamp"
	// RequireVulnerabilities demands no vulnerability information.
	RequireVulnerabilities Requirement = "vulnerabilities"
)

// Profile is a named, versioned requirement set taken from a published
// guideline. The name pins the guideline version.
type Profile struct {
	Name             string
	Guideline        string
	GuidelineVersion string
}

// ProfileBSITR031832v210 is the only known profile. It checks presence and
// form of the fields BSI TR-03183-2 2.1.0 makes MUST; a pass does not
// establish that the values are correct or complete.
const ProfileBSITR031832v210 = "bsi-tr-03183-2@2.1.0"

var profiles = map[string]Profile{
	ProfileBSITR031832v210: {Name: ProfileBSITR031832v210, Guideline: "BSI TR-03183-2", GuidelineVersion: "2.1.0"},
}

// LookupProfile returns the profile called name.
func LookupProfile(name string) (Profile, bool) {
	p, ok := profiles[name]
	return p, ok
}

// LevelProperty is the CycloneDX property a producer uses to mark the level a
// component is described at. The TR defines no field for it (§3.1 permits the
// extension).
const LevelProperty = "rio:tr-03183-2:level"

// The levels a component is checked at. referenced is inferred from a bom
// external reference and is never accepted as a LevelProperty value.
const (
	LevelFull       = "full"
	LevelLogical    = "logical"
	LevelAssembled  = "assembled"
	LevelIdentified = "identified"
	LevelReferenced = "referenced"
)

// BSI property taxonomy names and their allowed values, verbatim.
const (
	propFilename   = "bsi:component:filename"
	propExecutable = "bsi:component:executable"
	propArchive    = "bsi:component:archive"
	propStructured = "bsi:component:structured"
)

// profileFields is every per-component profile field in reporting order,
// after name, version (and purl) and before securityContact and digest.
var profileFields = []Requirement{
	RequireLevel, RequireCreator, RequireFilename, RequireDependencies, RequireDistributionLicences,
	RequireDeployableHash, RequireExecutable, RequireArchive, RequireStructured,
}

// sbomFields is the sbom scope in reporting order.
var sbomFields = []Requirement{RequireSpecVersion, RequireCreator, RequireTimestamp, RequireVulnerabilities}

// levelFields is what each level demands beyond name and version, which
// every level demands, and level itself, which is resolved for everything.
// An assembled part, such as a statically linked library, is not a file, so
// its filename, hash and file properties are not available and are omitted
// (§3.2.1).
var levelFields = map[string]map[Requirement]bool{
	LevelFull:       set(RequireCreator, RequireFilename, RequireDependencies, RequireDistributionLicences, RequireDeployableHash, RequireExecutable, RequireArchive, RequireStructured),
	LevelAssembled:  set(RequireCreator, RequireDependencies, RequireDistributionLicences),
	LevelLogical:    set(RequireCreator, RequireDependencies, RequireDistributionLicences),
	LevelIdentified: set(RequireCreator),
	LevelReferenced: set(RequireCreator),
}

func set(reqs ...Requirement) map[Requirement]bool {
	out := map[Requirement]bool{}
	for _, r := range reqs {
		out[r] = true
	}
	return out
}

// applies reports whether a component at level is checked for req.
func applies(level string, req Requirement) bool {
	return req == RequireLevel || levelFields[level][req]
}

// ProfileSection returns the TR section a failure ID comes from, such as
// "§5.2.2" for "components.filename", or "" for *.level (rio's own property)
// and for IDs no profile defines.
func ProfileSection(id string) string {
	scope, field, ok := strings.Cut(id, ".")
	if !ok {
		return ""
	}
	switch scope {
	case "sbom":
		switch Requirement(field) {
		case RequireSpecVersion:
			return "§4"
		case RequireCreator, RequireTimestamp:
			return "§5.2.1"
		case RequireVulnerabilities:
			return "§3.1"
		}
	case "subject", "components":
		switch Requirement(field) {
		case RequireDistributionLicences:
			return "§5.2.2, §6.1"
		case RequireName, RequireVersion, RequireCreator, RequireFilename, RequireDependencies,
			RequireDeployableHash, RequireExecutable, RequireArchive, RequireStructured:
			return "§5.2.2"
		}
	}
	return ""
}

// profileRun is one profile evaluation over one document.
type profileRun struct {
	doc      *sbom.Document
	deps     map[string]bool
	covered  map[string]bool
	levels   map[string]int
	subject  *checkedComponent
	children []checkedComponent
}

// checkedComponent is one component's level and failed profile fields.
type checkedComponent struct {
	ref     sbom.ComponentRef
	level   string
	missing map[Requirement]bool
	details map[string]string
}

func runProfile(doc *sbom.Document) *profileRun {
	run := &profileRun{
		doc:     doc,
		deps:    doc.DependencyEntries(),
		covered: doc.CompositionCoverage(),
		levels:  map[string]int{LevelFull: 0, LevelLogical: 0, LevelAssembled: 0, LevelIdentified: 0, LevelReferenced: 0},
	}
	for _, c := range doc.ProfileComponents() {
		checked := run.check(c)
		run.levels[checked.level]++
		if c.Subject {
			run.subject = &checked
			continue
		}
		run.children = append(run.children, checked)
	}
	return run
}

// validSpecVersion reports a dotted decimal version of CycloneDX 1.6 or later.
// A segment that is not a plain decimal number fails, whatever compareSpecVersions
// would make of it.
func validSpecVersion(v string) bool {
	for _, seg := range strings.Split(v, ".") {
		if seg == "" {
			return false
		}
		for _, c := range seg {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return sbom.AtLeast(v, "1.6")
}

// sbomMissing returns the failed sbom-scope requirements in reporting order.
func (run *profileRun) sbomMissing() []string {
	meta := run.doc.MetadataObject()
	failed := map[Requirement]bool{
		RequireSpecVersion:     !validSpecVersion(run.doc.SpecVersion()),
		RequireCreator:         !validCreator(meta["manufacturer"]),
		RequireTimestamp:       !validTimestamp(meta["timestamp"]),
		RequireVulnerabilities: run.doc.HasVulnerabilities(),
	}
	var missing []string
	for _, r := range sbomFields {
		if failed[r] {
			missing = append(missing, string(r))
		}
	}
	return missing
}

// check resolves c's level and runs the field checks that level demands.
// Name and version are left to the callers, which already check them.
func (run *profileRun) check(c sbom.ComponentObject) checkedComponent {
	obj := c.Object
	out := checkedComponent{
		ref: sbom.ComponentRef{
			Path: c.Path, Group: str(obj, "group"), Name: str(obj, "name"),
			Version: str(obj, "version"), PURL: str(obj, "purl"),
		},
		missing: map[Requirement]bool{},
	}
	level, detail := resolveLevel(obj)
	out.level = level
	if detail != "" {
		out.missing[RequireLevel] = true
		out.details = map[string]string{string(RequireLevel): detail}
	}
	checks := map[Requirement]func(map[string]any) bool{
		RequireCreator:              func(o map[string]any) bool { return validCreator(o["manufacturer"]) },
		RequireFilename:             validFilename,
		RequireDependencies:         run.validDependencies,
		RequireDistributionLicences: validLicences,
		RequireDeployableHash:       validDeployableHash,
		RequireExecutable:           func(o map[string]any) bool { return oneProperty(o, propExecutable, "executable", "non-executable") },
		RequireArchive:              func(o map[string]any) bool { return oneProperty(o, propArchive, "archive", "no archive") },
		RequireStructured:           func(o map[string]any) bool { return oneProperty(o, propStructured, "structured", "unstructured") },
	}
	for req, ok := range checks {
		if applies(level, req) && !ok(obj) {
			out.missing[req] = true
		}
	}
	return out
}

// resolveLevel returns the level obj is checked at, and a detail when its
// level property is unusable. A bom external reference with a nonblank url
// makes a component referenced whatever its property says; the property is
// then not read. A bom reference that does not identify another BOM counts
// for nothing. An unusable property leaves the component checked as full.
func resolveLevel(obj map[string]any) (level, detail string) {
	for _, ref := range objects(obj["externalReferences"]) {
		if url, ok := ref["url"].(string); ok && ref["type"] == "bom" && !blank(url) {
			return LevelReferenced, ""
		}
	}
	values := properties(obj, LevelProperty)
	switch {
	case len(values) == 0:
		return LevelFull, ""
	case len(values) > 1:
		return LevelFull, fmt.Sprintf("the %s property appears %d times; it may appear once", LevelProperty, len(values))
	}
	s, ok := values[0].(string)
	switch {
	case ok && (s == LevelLogical || s == LevelIdentified || s == LevelAssembled):
		return s, ""
	case ok:
		return LevelFull, fmt.Sprintf("the %s value %q is not %s, %s or %s", LevelProperty, s, LevelLogical, LevelIdentified, LevelAssembled)
	default:
		return LevelFull, fmt.Sprintf("the %s value is not a string", LevelProperty)
	}
}

// checkProfile is CheckRequirements under profile p. It reports one finding
// for the document, one for the subject and one per failing component, each
// merging the profile's fields with gate.require and gate.subject.require in
// the fixed reporting order. Components are checked at their level; name and
// version are demanded of every component at every level whatever
// gate.require says.
func checkProfile(doc *sbom.Document, reqs Requirements, p Profile) Result {
	run := runProfile(doc)
	result := Result{Findings: []Finding{}, ComponentCount: len(run.children), Profile: &p, ProfileLevels: run.levels}

	if missing := run.sbomMissing(); len(missing) > 0 {
		f := Finding{SBOM: true, Missing: missing}
		if !validSpecVersion(doc.SpecVersion()) {
			f.Details = map[string]string{string(RequireSpecVersion): doc.SpecVersion()}
		}
		result.Findings = append(result.Findings, f)
	}

	// The subject: name and version as always, the profile fields when
	// metadata.component is an object, then the opted-in subject fields.
	base, _ := checkSubject(doc, reqs.Subject)
	subject := Finding{Subject: true, Details: base.Details}
	has := set()
	for _, m := range base.Missing {
		has[Requirement(m)] = true
	}
	if run.subject != nil {
		for r := range run.subject.missing {
			has[r] = true
		}
		subject.Details = mergeDetails(subject.Details, run.subject.details)
	}
	for _, r := range subjectOrder() {
		if has[r] {
			subject.Missing = append(subject.Missing, string(r))
		}
	}
	if len(subject.Missing) > 0 {
		result.Findings = append(result.Findings, subject)
	}

	wantPURL := wants(reqs.Components, RequirePURL)
	for _, c := range run.children {
		var missing []string
		if blank(c.ref.Name) {
			missing = append(missing, string(RequireName))
		}
		if blank(c.ref.Version) {
			missing = append(missing, string(RequireVersion))
		}
		if wantPURL && !validPURL(c.ref.PURL) {
			missing = append(missing, string(RequirePURL))
		}
		for _, r := range profileFields {
			if c.missing[r] {
				missing = append(missing, string(r))
			}
		}
		if len(missing) > 0 {
			result.Findings = append(result.Findings, Finding{Component: identify(c.ref), Missing: missing, Details: c.details})
		}
	}

	result.Evaluations = run.evaluations(reqs, result.Findings)
	return result
}

// subjectOrder is the subject's reporting order under a profile.
func subjectOrder() []Requirement {
	order := []Requirement{RequireName, RequireVersion}
	order = append(order, profileFields...)
	return append(order, RequireSecurityContact, RequireDigest)
}

func mergeDetails(a, b map[string]string) map[string]string {
	if len(b) == 0 {
		return a
	}
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// evaluations lists every requirement the profile run evaluated, in reporting
// order, with the number of components it was evaluated for and how often it
// failed. Its shape is ProfileEvaluationCounts for this document.
func (run *profileRun) evaluations(reqs Requirements, findings []Finding) []Evaluation {
	subjectLevel := ""
	if run.subject != nil {
		subjectLevel = run.subject.level
	}
	children := map[string]int{}
	for _, c := range run.children {
		children[c.level]++
	}
	out := ProfileEvaluationCounts(subjectLevel, children, reqs)
	for i, e := range out {
		out[i] = evaluate(e.Scope, Requirement(e.Requirement), e.Evaluated, findings)
	}
	return out
}

// ProfileEvaluationCounts is the evaluation list a profile run reports, in
// reporting order, with each entry's Evaluated count and nothing else: the sbom
// scope; the subject's name and version; every profile field for a subject at
// subjectLevel ("" when metadata.component is not an object, which evaluates
// none); the subject fields reqs.Subject opts into; the components' name,
// version and, when reqs.Components opts into it, purl; then every profile
// field, counted over the components at each level in children. A field no
// level demanded is listed with count 0, so the list has the same entries for
// every document under the same opt-ins. A reader of recorded evaluations
// checks them against it.
func ProfileEvaluationCounts(subjectLevel string, children map[string]int, reqs Requirements) []Evaluation {
	count := func(scope string, r Requirement, n int) Evaluation {
		return Evaluation{Scope: scope, Requirement: string(r), Evaluated: n}
	}
	out := []Evaluation{}
	for _, r := range sbomFields {
		out = append(out, count("sbom", r, 1))
	}

	out = append(out, count("subject", RequireName, 1), count("subject", RequireVersion, 1))
	for _, r := range profileFields {
		n := 0
		if subjectLevel != "" && applies(subjectLevel, r) {
			n = 1
		}
		out = append(out, count("subject", r, n))
	}
	for _, r := range []Requirement{RequireSecurityContact, RequireDigest} {
		if wants(reqs.Subject, r) {
			out = append(out, count("subject", r, 1))
		}
	}

	total := 0
	for _, n := range children {
		total += n
	}
	out = append(out, count("components", RequireName, total), count("components", RequireVersion, total))
	if wants(reqs.Components, RequirePURL) {
		out = append(out, count("components", RequirePURL, total))
	}
	for _, r := range profileFields {
		n := 0
		for level, k := range children {
			if applies(level, r) {
				n += k
			}
		}
		out = append(out, count("components", r, n))
	}
	return out
}
