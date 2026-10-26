package gate

import (
	"net/url"
	"strings"
	"time"

	"github.com/rebaze/rio/internal/sbom"
)

// The field checks a requirement profile runs. Each reads raw JSON and treats
// a value of the wrong shape as absent, so a malformed document produces
// findings rather than a panic. None of them modifies what it reads.

// validCreator passes a manufacturer object with a contact email that has text
// on both sides of an "@", or an absolute http(s) URL that names a host.
func validCreator(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for _, c := range objects(m["contact"]) {
		if email, ok := c["email"].(string); ok {
			email = strings.TrimSpace(email)
			if at := strings.Index(email, "@"); at > 0 && at < len(email)-1 {
				return true
			}
		}
	}
	urls, _ := m["url"].([]any)
	for _, u := range urls {
		if s, ok := u.(string); ok && absoluteHTTP(s) {
			return true
		}
	}
	return false
}

func absoluteHTTP(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	return err == nil && (strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")) && u.Hostname() != ""
}

func validTimestamp(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}

// validFilename passes exactly one bsi:component:filename that is nonblank and
// names a file rather than a path.
func validFilename(obj map[string]any) bool {
	values := properties(obj, propFilename)
	if len(values) != 1 {
		return false
	}
	s, ok := values[0].(string)
	return ok && !blank(s) && !strings.ContainsAny(s, `/\`)
}

// oneProperty passes exactly one property called name with an allowed value.
func oneProperty(obj map[string]any, name string, allowed ...string) bool {
	values := properties(obj, name)
	if len(values) != 1 {
		return false
	}
	s, ok := values[0].(string)
	if !ok {
		return false
	}
	for _, a := range allowed {
		if s == a {
			return true
		}
	}
	return false
}

// validDeployableHash passes any SHA-512 of 128 hex characters on a
// distribution reference.
func validDeployableHash(obj map[string]any) bool {
	for _, ref := range objects(obj["externalReferences"]) {
		if ref["type"] != DistributionReference {
			continue
		}
		for _, h := range objects(ref["hashes"]) {
			if content, ok := h["content"].(string); ok && h["alg"] == "SHA-512" && validHex(content, 128) {
				return true
			}
		}
	}
	return false
}

// validDependencies passes a component whose string bom-ref has its own
// dependencies entry and is covered by a composition.
func (run *profileRun) validDependencies(obj map[string]any) bool {
	ref, ok := obj["bom-ref"].(string)
	return ok && !blank(ref) && run.deps[ref] && run.covered[ref]
}

// validLicences passes a concluded licence in SPDX form: an expression entry
// acknowledged as concluded, or a license with a known SPDX id acknowledged
// as concluded. A licence name or text alone never counts (§6.1).
func validLicences(obj map[string]any) bool {
	for _, e := range objects(obj["licenses"]) {
		if expr, ok := e["expression"].(string); ok && e["acknowledgement"] == "concluded" && validSPDXExpression(expr) {
			return true
		}
		if l, ok := e["license"].(map[string]any); ok && l["acknowledgement"] == "concluded" {
			if id, ok := l["id"].(string); ok && sbom.KnownSPDXIdentifier(id) {
				return true
			}
		}
	}
	return false
}

// objects returns the object entries of v when v is an array, skipping
// anything else; a wrong shape reads as absent, so it becomes a finding.
func objects(v any) []map[string]any {
	list, _ := v.([]any)
	var out []map[string]any
	for _, e := range list {
		if o, ok := e.(map[string]any); ok {
			out = append(out, o)
		}
	}
	return out
}

// properties returns the values of every property called name.
func properties(obj map[string]any, name string) []any {
	var out []any
	for _, p := range objects(obj["properties"]) {
		if p["name"] == name {
			out = append(out, p["value"])
		}
	}
	return out
}

func str(obj map[string]any, key string) string {
	s, _ := obj[key].(string)
	return s
}

func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
