// Package gate answers one question per artifact: is this SBOM good enough to
// hand on? It reads a loaded document and reports findings (§5 step 4).
//
// The gate never modifies the document and never repairs anything. Repair is
// the transform layer's job and it happens first; whatever identity is missing
// by the time the gate runs is missing for real. In particular a component
// without a version is reported, never given "unknown" or "0.0.0", because a
// wrong version travels further than a missing one.
//
// Gate failures are results, not errors. They are recorded in index.json and
// reflected in the exit code, so nothing here returns an error (§10).
package gate

import (
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/rebaze/rio/internal/sbom"
)

// Requirement is one field the manifest's gate.require can ask for.
type Requirement string

const (
	// RequireName demands a present, non-empty component.name.
	RequireName Requirement = "name"
	// RequireVersion demands a present, non-empty component.version.
	RequireVersion Requirement = "version"
	// RequirePURL demands a present component.purl that parses as a package
	// URL.
	RequirePURL Requirement = "purl"
)

// All returns every requirement, which is what gate.require defaults to (§2).
// The order is the reporting order used by Finding.Missing.
func All() []Requirement {
	return []Requirement{RequireName, RequireVersion, RequirePURL}
}

// Finding is one gate failure. internal/index carries its own GateFinding for
// the on-disk shape and the caller converts, so the wire contract in §4.2 has
// exactly one owner; the tags here keep the two readable side by side.
type Finding struct {
	// Subject marks the finding as being about metadata.component rather than
	// a member of the components array.
	Subject bool `json:"subject,omitempty"`
	// Component names the offending component for a human: its purl where it
	// has one, otherwise a group:name@version rendering, otherwise its index.
	// Empty on a subject finding, which index.json already attributes by
	// artifact id.
	Component string `json:"component,omitempty"`
	// Missing lists the failed requirements in the fixed order name, version,
	// purl, never the order gate.require gave them in (§7).
	Missing []string `json:"missing"`
}

// Result is the outcome of a gate run.
type Result struct {
	// Findings is the subject finding first, if any, then the failing
	// components in document order. Never nil, so index.json carries an empty
	// array rather than null.
	Findings []Finding
}

// OK reports whether the artifact passed.
func (r Result) OK() bool { return len(r.Findings) == 0 }

// Check evaluates doc against require and returns what failed.
//
// The document's subject is always checked, whatever require contains: an
// artifact with no identity of its own cannot be recorded against, and the
// DependencyTrack project version is read straight out of it (§4.3d).
// Requirements the gate does not recognise are ignored; the manifest loader is
// what rejects them (§2).
func Check(doc *sbom.Document, require []Requirement) Result {
	findings := []Finding{}
	if doc == nil {
		return Result{Findings: findings}
	}

	if f, failed := checkSubject(doc); failed {
		findings = append(findings, f)
	}

	wantName, wantVersion, wantPURL := false, false, false
	for _, r := range require {
		switch r {
		case RequireName:
			wantName = true
		case RequireVersion:
			wantVersion = true
		case RequirePURL:
			wantPURL = true
		}
	}
	if !wantName && !wantVersion && !wantPURL {
		return Result{Findings: findings}
	}

	// Every component, including components nested under another: a nested
	// component is still shipped, and §5 step 4 says every one is evaluated.
	// The gate only reads, so unlike the transform layer it is not bound to
	// the top-level array that §8's join by index addresses.
	for _, c := range doc.EveryComponent() {
		// Fixed order, independent of the order require arrived in (§7).
		var missing []string
		if wantName && blank(c.Name) {
			missing = append(missing, string(RequireName))
		}
		if wantVersion && blank(c.Version) {
			missing = append(missing, string(RequireVersion))
		}
		if wantPURL && !validPURL(c.PURL) {
			missing = append(missing, string(RequirePURL))
		}
		if len(missing) > 0 {
			findings = append(findings, Finding{Component: identify(c), Missing: missing})
		}
	}

	return Result{Findings: findings}
}

// checkSubject verifies metadata.component carries both a name and a version.
func checkSubject(doc *sbom.Document) (Finding, bool) {
	name, version := doc.Subject()
	var missing []string
	if blank(name) {
		missing = append(missing, string(RequireName))
	}
	if blank(version) {
		missing = append(missing, string(RequireVersion))
	}
	if len(missing) == 0 {
		return Finding{}, false
	}
	return Finding{Subject: true, Missing: missing}, true
}

// validPURL reports whether purl is present and parses as a package URL.
//
// Parsing is delegated to packageurl-go rather than pattern matched here, so
// the gate agrees with every other purl consumer in the estate. A purl the
// p2 transform could not map is still a purl and still passes: unmapped is a
// count in index.json, not a gate failure (§5 step 4).
func validPURL(purl string) bool {
	if blank(purl) {
		return false
	}
	_, err := packageurl.FromString(purl)
	return err == nil
}

// blank reports whether a required field is absent or effectively empty. A
// name of "   " is present but not identity, and it would reach
// DependencyTrack as a whitespace project name (§5 step 4, §4.3d).
func blank(s string) bool { return strings.TrimSpace(s) == "" }

// identify renders a component in the most recognisable form it can support,
// so a finding is actionable without opening the SBOM.
func identify(c sbom.ComponentRef) string {
	if !blank(c.PURL) {
		// Reported verbatim even when it failed to parse: the broken string is
		// exactly what the reader has to go and fix.
		return c.PURL
	}

	group, name := strings.TrimSpace(c.Group), strings.TrimSpace(c.Name)
	var id string
	switch {
	case group != "" && name != "":
		id = group + ":" + name
	case name != "":
		id = name
	case group != "":
		id = group
	default:
		// No name of its own, so locate it positionally instead. Nested
		// components make the path the only unambiguous locator.
		id = c.Path
	}

	// The version is appended even to a positional identifier: it is the only
	// value a version-only component has, and dropping it makes the finding
	// harder to act on than the data allows (§10).
	if version := strings.TrimSpace(c.Version); version != "" {
		id += "@" + version
	}
	return id
}
