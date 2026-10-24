package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/rebaze/rio/internal/gate"
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
