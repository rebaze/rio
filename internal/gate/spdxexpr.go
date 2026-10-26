package gate

import (
	"strings"

	"github.com/rebaze/rio/internal/sbom"
)

// Bounds on untrusted input: the parser recurses once per "(".
const (
	maxSPDXExpressionLen   = 4096
	maxSPDXExpressionDepth = 64
)

// validSPDXExpression reports whether s is an SPDX licence expression whose
// identifiers rio can vouch for: ids from the embedded SPDX list (optionally
// with a trailing "+"), LicenseRef-… and DocumentRef-…:LicenseRef-…, joined
// with AND, OR and WITH (uppercase or all lowercase) and parentheses. The
// right side of WITH is an id from the same list.
//
// It checks form only. A well-formed expression can still name the wrong
// licence.
//
//	expr := and ("OR" and)*
//	and  := with ("AND" with)*
//	with := id ["WITH" exception] | "(" expr ")"
func validSPDXExpression(s string) bool {
	if len(s) > maxSPDXExpressionLen {
		return false
	}
	tokens := spdxTokens(s)
	if len(tokens) == 0 {
		return false
	}
	p := &spdxParser{tokens: tokens}
	return p.expr() && p.pos == len(p.tokens)
}

// spdxTokens splits s into parentheses and words. The parser rejects words
// that are neither ids nor operators.
func spdxTokens(s string) []string {
	var tokens []string
	word := strings.Builder{}
	flush := func() {
		if word.Len() > 0 {
			tokens = append(tokens, word.String())
			word.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '(' || r == ')':
			flush()
			tokens = append(tokens, string(r))
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			flush()
		default:
			word.WriteRune(r)
		}
	}
	flush()
	return tokens
}

type spdxParser struct {
	tokens []string
	pos    int
	depth  int
}

func (p *spdxParser) peek() string {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return ""
}

// operator consumes the next token when it is op in uppercase or all
// lowercase. Mixed case ("And") is neither an operator nor a known id.
func (p *spdxParser) operator(op string) bool {
	t := p.peek()
	if t == op || t == strings.ToLower(op) {
		p.pos++
		return true
	}
	return false
}

func (p *spdxParser) expr() bool {
	if !p.and() {
		return false
	}
	for p.operator("OR") {
		if !p.and() {
			return false
		}
	}
	return true
}

func (p *spdxParser) and() bool {
	if !p.with() {
		return false
	}
	for p.operator("AND") {
		if !p.with() {
			return false
		}
	}
	return true
}

func (p *spdxParser) with() bool {
	t := p.peek()
	if t == "(" {
		p.pos++
		p.depth++
		if p.depth > maxSPDXExpressionDepth {
			return false
		}
		if !p.expr() || p.peek() != ")" {
			return false
		}
		p.depth--
		p.pos++
		return true
	}
	if t == "" || t == ")" || isSPDXOperator(t) || !validLicenceID(t) {
		return false
	}
	p.pos++
	if p.operator("WITH") {
		exc := p.peek()
		if exc == "" || isSPDXOperator(exc) || !validIDChars(exc) || !sbom.KnownSPDXIdentifier(exc) {
			return false
		}
		p.pos++
	}
	return true
}

func isSPDXOperator(t string) bool {
	switch t {
	case "AND", "OR", "WITH", "and", "or", "with":
		return true
	}
	return false
}

// validLicenceID accepts a known SPDX id with an optional trailing "+",
// LicenseRef-… and DocumentRef-…:LicenseRef-….
func validLicenceID(t string) bool {
	if validLicenseRef(t) {
		return true
	}
	if doc, ref, ok := strings.Cut(t, ":"); ok && strings.HasPrefix(doc, "DocumentRef-") {
		return validIDChars(strings.TrimPrefix(doc, "DocumentRef-")) && validLicenseRef(ref)
	}
	id := strings.TrimSuffix(t, "+")
	return validIDChars(id) && sbom.KnownSPDXIdentifier(id)
}

func validLicenseRef(t string) bool {
	rest, ok := strings.CutPrefix(t, "LicenseRef-")
	return ok && validIDChars(rest)
}

// validIDChars reports a nonempty run of [A-Za-z0-9.-].
func validIDChars(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}
