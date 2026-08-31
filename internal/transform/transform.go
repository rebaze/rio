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

// Describer reports what a transform's configuration resolves to WITHOUT
// building the transform, for `rio plan`.
//
// The two are not the same call with the output thrown away. A factory is
// free to touch the filesystem -- repair-purl/p2 reads its mapping table --
// and that table is the very file the plan exists to help produce, so a
// describe routed through New could never describe the run that bootstraps
// it. A Describer therefore validates the configuration and nothing else: it
// must reject exactly what its factory rejects, and read nothing.
//
// Options come back resolved, defaults filled in, in an order the transform
// owns, so a plan is byte identical across runs (§7).
type Describer func(cfg Config) ([]Option, error)

// Option is one resolved configuration key of a described transform.
type Option struct {
	// Key is the manifest key, spelled the way the manifest spells it.
	Key string
	// Value is what is in force once the defaults are applied. A consumer
	// reads this rather than carrying its own copy of a default, which is the
	// point of publishing a plan at all.
	Value string
	// IsDefault is true when Value is what would apply with the manifest
	// silent. It is what lets a human readable plan show only the options a
	// manifest actually changed, without the reader having to know which
	// values are the standard ones.
	IsDefault bool
	// Path is true when Value names a file, resolved against the manifest's
	// own directory like every other path in a transform's configuration.
	// It is what lets `rio plan` report that a mapping table does not exist
	// yet without knowing whose option it is looking at.
	Path bool
}

// entry is one registered transform. The factory and the describer live in
// one record rather than in two registries, because two could disagree about
// which names exist and a transform that is buildable but not describable
// would drop out of `rio plan` silently.
type entry struct {
	factory   Factory
	describer Describer
}

var registry = map[string]entry{}

// Register adds a transform under its manifest key. It panics on a duplicate,
// or on a half-registration, which can only be a programming error at init
// time.
func Register(name string, f Factory, d Describer) {
	if _, exists := registry[name]; exists {
		panic("transform registered twice: " + name)
	}
	if f == nil || d == nil {
		panic("transform " + name + " needs both a factory and a describer")
	}
	registry[name] = entry{factory: f, describer: d}
}

// Names lists every registered transform name, sorted.
func Names() []string {
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
	e, ok := registry[name]
	if !ok {
		return nil, unknownTransform(name)
	}
	if cfg == nil {
		cfg = Config{}
	}
	return e.factory(cfg, baseDir)
}

// Describe resolves a transform's configuration without building it. It
// reports the same unknown-name error New does, so a manifest `rio plan`
// accepts is one `rio normalize` will also get past this point (§10).
func Describe(name string, cfg Config) ([]Option, error) {
	e, ok := registry[name]
	if !ok {
		return nil, unknownTransform(name)
	}
	if cfg == nil {
		cfg = Config{}
	}
	return e.describer(cfg)
}

func unknownTransform(name string) error {
	return fmt.Errorf("unknown transform %q, known transforms are %s",
		name, strings.Join(Names(), ", "))
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
