package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/rebaze/rio/internal/gate"
	"github.com/rebaze/rio/internal/receipt"
)

// explainGate prints, for one artifact that failed the gate, each failed
// requirement with what its producer can do about it. The consequence line
// comes from the caller, which knows whether delivery was attempted.
//
// The advice names only places where the information can be supplied: the
// SBOM generator, or reviewed values in rio.yaml. Rio never looks up, guesses
// or fills in a value to make a requirement pass.
func explainGate(w io.Writer, id, consequence string, r gate.Result) {
	fmt.Fprintf(w, "rio: artifact %q failed the gate; %s\n", id, consequence)
	for _, line := range gateExplanations(r) {
		fmt.Fprintf(w, "  %s\n", line)
	}
}

func gateExplanations(r gate.Result) []string {
	if r.Profile != nil {
		return profileExplanations(r)
	}
	var lines []string
	components := map[string]int{}
	example := map[string]string{}
	for _, f := range r.Findings {
		if f.Subject {
			for _, m := range f.Missing {
				lines = append(lines, "subject."+m+": "+subjectAdvice(m, f.Details[m]))
			}
			continue
		}
		for _, m := range f.Missing {
			if components[m] == 0 {
				example[m] = f.Component
			}
			components[m]++
		}
	}
	for _, req := range gate.All() {
		m := string(req)
		n := components[m]
		if n == 0 {
			continue
		}
		what := "no " + m
		if req == gate.RequirePURL {
			what = "no valid package URL"
		}
		// %q: the example comes from the SBOM and may hold control characters.
		lines = append(lines, fmt.Sprintf("components.%s: %s %s, for example %q. Fix the SBOM generator, or remove %s from gate.require if this handoff does not need it.",
			m, plural(n, "component"), hasHave(n)+" "+what, example[m], m))
	}
	return lines
}

func subjectAdvice(field, detail string) string {
	switch field {
	case string(gate.RequireSecurityContact):
		if detail != "" {
			return strings.ToUpper(detail[:1]) + detail[1:] + ". Fix the SBOM generator, or set the reviewed contact as enrichment.subject.securityContact in rio.yaml and list subject.securityContact in enrichment.replace."
		}
		return "the SBOM subject has no security-contact reference. Set the reviewed contact as enrichment.subject.securityContact in rio.yaml, or have the SBOM generator emit one. Rio does not look it up."
	case string(gate.RequireDigest):
		return "the SBOM subject has no distribution digest. Add the shipped files under distributions in the build context file. Rio does not hash them."
	default:
		return fmt.Sprintf("the SBOM subject (metadata.component) has no %s. Fix the SBOM generator, or set it with artifacts[].subject or enrichment.subject.%s in rio.yaml.", field, field)
	}
}

func hasHave(n int) string {
	if n == 1 {
		return "has"
	}
	return "have"
}

// profileExplanations is gateExplanations under a requirement profile: one
// line per failed ID in the receipt's fixed order (sbom, subject, components),
// each naming the TR section it comes from where there is one.
func profileExplanations(r gate.Result) []string {
	type tally struct {
		n       int
		example string
		detail  string
	}
	found := map[string]*tally{}
	for _, f := range r.Findings {
		scope := findingScope(f.SBOM, f.Subject)
		for _, m := range f.Missing {
			id := scope + "." + m
			t := found[id]
			if t == nil {
				t = &tally{example: f.Component, detail: f.Details[m]}
				found[id] = t
			}
			t.n++
		}
	}
	var lines []string
	for _, id := range receipt.FailedRequirementIDs() {
		t := found[id]
		if t == nil {
			continue
		}
		scope, field, _ := strings.Cut(id, ".")
		label := id
		if section := gate.ProfileSection(id); section != "" {
			label = fmt.Sprintf("%s (%s %s %s)", id, r.Profile.Guideline, r.Profile.GuidelineVersion, section)
		}
		switch scope {
		case "sbom":
			lines = append(lines, label+": "+sbomAdvice(field, t.detail))
		case "subject":
			lines = append(lines, label+": "+profileSubjectAdvice(field, t.detail))
		default:
			lines = append(lines, label+": "+profileComponentAdvice(field, t.n, t.example, t.detail))
		}
	}
	return lines
}

func sbomAdvice(field, detail string) string {
	switch field {
	case string(gate.RequireSpecVersion):
		return fmt.Sprintf("the SBOM declares specVersion %q, which is not CycloneDX 1.6 or later. Fix the SBOM generator.", detail)
	case string(gate.RequireCreator):
		return "the SBOM has no creator (metadata.manufacturer with a contact email or URL). Set enrichment.producer in rio.yaml, or have the SBOM generator emit one."
	case string(gate.RequireTimestamp):
		return "the SBOM has no timestamp (metadata.timestamp in RFC 3339 form). Have the SBOM generator emit it."
	default:
		return "the SBOM contains vulnerability information. Deliver vulnerability information separately, for example as VEX; the TR forbids it in the SBOM."
	}
}

// profileNoun says what a profile field is, for "has no <noun>".
func profileNoun(field string) string {
	switch field {
	case string(gate.RequireCreator):
		return "creator (manufacturer)"
	case string(gate.RequireFilename):
		return "filename (bsi:component:filename)"
	case string(gate.RequireDependencies):
		return "dependencies entry covered by a compositions entry"
	case string(gate.RequireDistributionLicences):
		return "concluded licence in SPDX form"
	case string(gate.RequireDeployableHash):
		return "SHA-512 hash on a distribution reference"
	case string(gate.RequireExecutable):
		return "bsi:component:executable property (executable or non-executable)"
	case string(gate.RequireArchive):
		return "bsi:component:archive property (archive or no archive)"
	case string(gate.RequireStructured):
		return "bsi:component:structured property (structured or unstructured)"
	}
	return field
}

const emitAdvice = "Have the SBOM generator emit it."

// profileFix is who can fix a profile field, for the fields that have more to
// say than "have the generator emit it".
func profileFix(scope, field string) string {
	const logical = "if the subject is a product rather than one shipped file, declare it logical with level in the build context file or rio:tr-03183-2:level from the generator"
	switch field {
	case string(gate.RequireCreator):
		if scope == "subject" {
			return "Set enrichment.subject.manufacturer in rio.yaml, or have the SBOM generator emit one."
		}
	case string(gate.RequireDeployableHash):
		if scope == "subject" {
			return "Have the SBOM generator emit it, or, " + logical + "; list the shipped files with sha512 under distributions in the build context file. Rio does not hash files."
		}
		return "Have the SBOM generator emit it, or mark components that do not exist as a file of their own (for example statically linked libraries) as assembled with rio:tr-03183-2:level. Rio does not hash files."
	case string(gate.RequireFilename), string(gate.RequireExecutable), string(gate.RequireArchive), string(gate.RequireStructured):
		if scope == "subject" {
			return "Have the SBOM generator emit it, or, " + logical + "."
		}
	}
	return emitAdvice
}

const levelFix = "Set it once to logical, identified or assembled, or remove the property."

func levelSentence(detail string) string {
	if detail == "" {
		return "the rio:tr-03183-2:level property is not valid"
	}
	return detail
}

func profileSubjectAdvice(field, detail string) string {
	switch field {
	case string(gate.RequireSecurityContact), string(gate.RequireDigest):
		return subjectAdvice(field, detail)
	case string(gate.RequireName), string(gate.RequireVersion):
		return subjectAdvice(field, detail)
	case string(gate.RequireLevel):
		s := levelSentence(detail)
		return strings.ToUpper(s[:1]) + s[1:] + ". " + levelFix
	}
	return "the SBOM subject has no " + profileNoun(field) + ". " + profileFix("subject", field)
}

func profileComponentAdvice(field string, n int, example, detail string) string {
	// %q: the example comes from the SBOM and may hold control characters.
	switch field {
	case string(gate.RequirePURL):
		return fmt.Sprintf("%s %s no valid package URL, for example %q. Fix the SBOM generator, or remove purl from gate.require if this handoff does not need it.", plural(n, "component"), hasHave(n), example)
	case string(gate.RequireName), string(gate.RequireVersion):
		return fmt.Sprintf("%s %s no %s, for example %q. The TR requires it. %s", plural(n, "component"), hasHave(n), field, example, emitAdvice)
	case string(gate.RequireLevel):
		s := levelSentence(detail)
		return fmt.Sprintf("%s %s an invalid level, for example %q: %s. %s", plural(n, "component"), hasHave(n), example, s, levelFix)
	}
	return fmt.Sprintf("%s %s no %s, for example %q. %s", plural(n, "component"), hasHave(n), profileNoun(field), example, profileFix("components", field))
}

// findingScope is the scope part of a failed requirement ID.
func findingScope(sbom, subject bool) string {
	switch {
	case sbom:
		return "sbom"
	case subject:
		return "subject"
	}
	return "components"
}
