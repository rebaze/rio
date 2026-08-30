// Package transform defines the seam every document rewrite plugs into (§9b).
//
// A transform is named, configured from the manifest, applied in order, and
// reports what it changed rather than mutating opaquely. It never adds or
// removes components; the pipeline asserts that after each one.
package transform

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rebaze/rio/internal/sbom"
)

// Transform rewrites identity fields in a document.
type Transform interface {
	// ID names the transform in repair records and in index.json, e.g.
	// "repair-purl/p2".
	ID() string
	// Apply rewrites the document and reports what it did.
	Apply(doc *sbom.Document) (Result, error)
}

// Result is what one transform did to one document.
type Result struct {
	Changes []Change
	Notes   []Note
}

// Change is a field rio rewrote.
type Change struct {
	ComponentIndex int
	Field          string
	From           string
	To             string
}

// NoteKind distinguishes the two non-change outcomes.
type NoteKind string

const (
	// NoteUnmapped is a component in scope for the transform that it could
	// not resolve. Unmapped is a count, never a failure (§5 step 4).
	NoteUnmapped NoteKind = "unmapped"
	// NoteSkipped is a component the transform's scope filter excluded. It is
	// a third outcome, reported separately from unmapped (§6.2).
	NoteSkipped NoteKind = "skipped"
)

// Note is a component the transform did not change, and why.
type Note struct {
	ComponentIndex int
	Kind           NoteKind
	PURL           string
	Reason         string
}

// Config is a transform's manifest configuration.
type Config map[string]any

// Factory builds a transform from its manifest configuration. baseDir is the
// manifest's own directory, against which any path in the config resolves.
type Factory func(cfg Config, baseDir string) (Transform, error)

var registry = map[string]Factory{}

// Register adds a transform factory under its manifest key. It panics on a
// duplicate, which can only be a programming error at init time.
func Register(name string, f Factory) {
	if _, exists := registry[name]; exists {
		panic("transform registered twice: " + name)
	}
	registry[name] = f
}

// Known lists every registered transform name, sorted.
func Known() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// New builds a configured transform. An unknown name is a configuration error,
// which the caller turns into exit 2 (§2).
func New(name string, cfg Config, baseDir string) (Transform, error) {
	factory, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown transform %q, known transforms are %s",
			name, strings.Join(Known(), ", "))
	}
	if cfg == nil {
		cfg = Config{}
	}
	return factory(cfg, baseDir)
}

// String reads a string key. It reports an error when the key is present with
// a non-string value.
func (c Config) String(key, fallback string) (string, error) {
	v, ok := c[key]
	if !ok || v == nil {
		return fallback, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%q must be a string, got %T", key, v)
	}
	return s, nil
}

// Reject reports an error naming any key outside allowed, so a typo in the
// manifest fails loudly instead of being silently ignored.
func (c Config) Reject(allowed ...string) error {
	permitted := map[string]bool{}
	for _, k := range allowed {
		permitted[k] = true
	}
	var unknown []string
	for k := range c {
		if !permitted[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("unknown option(s) %s, known options are %s",
		strings.Join(unknown, ", "), strings.Join(allowed, ", "))
}
