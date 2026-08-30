// Package manifest loads and validates rio.yaml (§2).
//
// The manifest is the declared intent for a repository and is reviewed like
// code, so this package is strict: every problem it finds is a configuration
// error that aborts the run before any file is written, with a message naming
// the manifest path and the offending field (§10). Unknown keys are errors
// too, because a typo that is silently ignored produces a run that looks clean
// and did nothing.
//
// Paths inside the manifest are resolved by callers against Dir, the
// manifest's own directory, never against the process working directory.
package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rebaze/rio/internal/sbom"
	"github.com/rebaze/rio/internal/transform"
)

// Version is the only manifest version rio v1 understands. It is one of the
// two compatibility levers and is not bumped in v1 (§9).
const Version = 1

// The gate's requirable component fields (§2, §5 step 4).
const (
	RequireName    = "name"
	RequireVersion = "version"
	RequirePURL    = "purl"
)

// DefaultRequire is what gate.require means when it is not given.
func DefaultRequire() []string { return []string{RequireName, RequireVersion, RequirePURL} }

// DefaultSpecVersionFloor is what output.specVersionFloor means when it is not
// given (§2).
const DefaultSpecVersionFloor = "1.6"

// idPattern is the artifact id rule (§2). Ids become output filenames and
// DependencyTrack project names, so they must be filesystem and URL safe.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// Manifest is a loaded, validated rio.yaml.
type Manifest struct {
	Version   int
	Artifacts []Artifact
	Output    Output
	Gate      Gate

	// Path is the manifest path exactly as the caller gave it, which is what
	// index.json records (§4.2).
	Path string
	// Dir is the absolute directory holding the manifest. Globs and any path
	// in a transform config resolve against it (§2).
	Dir string
	// SHA256 is the lowercase hex digest of the manifest bytes. It is recorded
	// in every output (§2, §4.3a).
	SHA256 string
}

// Artifact is one entry under artifacts.
type Artifact struct {
	ID   string
	SBOM string
	// Subject overrides metadata.component when the generator described the
	// building module rather than the shipped artifact (§4.3d). Nil when the
	// manifest does not override it.
	Subject *Subject
	// Transforms are applied in the order given (§5 step 3).
	Transforms []TransformSpec
}

// Subject is the metadata.component override.
type Subject struct {
	Name    string
	Version string
}

// TransformSpec names one transform and carries its configuration.
//
// Config is a transform.Config so internal/transform can consume it without
// importing this package; the transform name is left unvalidated here because
// the registry owns the set of known names (§9b).
type TransformSpec struct {
	Name   string
	Config transform.Config
}

// Output is the output section.
type Output struct {
	SpecVersionFloor string
}

// Gate is the gate section.
type Gate struct {
	Require []string
}

// Requires reports whether field is one of the gate's required fields.
func (g Gate) Requires(field string) bool {
	for _, r := range g.Require {
		if r == field {
			return true
		}
	}
	return false
}

// Load reads, parses and validates the manifest at path.
func Load(path string) (*Manifest, error) {
	abs, absErr := filepath.Abs(path)
	if absErr != nil {
		// Only a broken working directory gets here.
		abs = path
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if abs != path {
				return nil, fmt.Errorf("manifest not found: %s (looked for %s)", path, abs)
			}
			return nil, fmt.Errorf("manifest not found: %s", path)
		}
		return nil, fmt.Errorf("read manifest %s: %w", path, err)
	}

	sum := sha256.Sum256(data)
	m := &Manifest{
		Path:   path,
		Dir:    filepath.Dir(abs),
		SHA256: hex.EncodeToString(sum[:]),
	}

	l := loader{path: path}

	var f fileSection
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// Unknown keys are errors: a misspelled key would otherwise be dropped
	// silently and the run would use defaults nobody asked for (§10).
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, l.errf("", "manifest is empty")
		}
		return nil, l.yamlError(err)
	}
	// A second document would be read by nobody and quietly ignored.
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, l.errf("", "manifest holds more than one YAML document, rio reads exactly one")
	} else if !errors.Is(err, io.EOF) {
		return nil, l.yamlError(err)
	}

	if err := l.version(&f, m); err != nil {
		return nil, err
	}
	if err := l.artifacts(&f, m); err != nil {
		return nil, err
	}
	if err := l.output(&f, m); err != nil {
		return nil, err
	}
	if err := l.gate(&f, m); err != nil {
		return nil, err
	}
	return m, nil
}

// fileSection is the on-disk shape. It is separate from Manifest so the
// validated result cannot express states the validation rejected, and so
// "absent" is distinguishable from "present and empty".
type fileSection struct {
	// Version is a Node rather than an int so a missing version and a
	// non-numeric one both get a message naming the field.
	Version   yaml.Node         `yaml:"version"`
	Artifacts []artifactSection `yaml:"artifacts"`
	Output    *outputSection    `yaml:"output"`
	Gate      *gateSection      `yaml:"gate"`
}

type artifactSection struct {
	ID      string          `yaml:"id"`
	SBOM    string          `yaml:"sbom"`
	Subject *subjectSection `yaml:"subject"`
	// Transforms stay as nodes: each entry is a single-key mapping whose key
	// is the transform name, which no Go struct describes.
	Transforms []yaml.Node `yaml:"transforms"`
}

type subjectSection struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
}

type outputSection struct {
	// A pointer separates "not given" (use the default) from an explicit
	// empty string (a mistake worth reporting).
	SpecVersionFloor *string `yaml:"specVersionFloor"`
}

type gateSection struct {
	Require *[]string `yaml:"require"`
}

// loader carries the manifest path so every message can name it (§10).
type loader struct{ path string }

func (l loader) errf(field, format string, a ...any) error {
	msg := fmt.Sprintf(format, a...)
	if field == "" {
		return fmt.Errorf("%s: %s", l.path, msg)
	}
	return fmt.Errorf("%s: %s: %s", l.path, field, msg)
}

func (l loader) version(f *fileSection, m *Manifest) error {
	if f.Version.IsZero() {
		return l.errf("version", "is required and must be %d", Version)
	}
	var v int
	if err := f.Version.Decode(&v); err != nil {
		return l.errf("version", "must be %d, got %s", Version, describe(&f.Version))
	}
	if v != Version {
		return l.errf("version", "must be %d, got %d", Version, v)
	}
	m.Version = v
	return nil
}

func (l loader) artifacts(f *fileSection, m *Manifest) error {
	if len(f.Artifacts) == 0 {
		return l.errf("artifacts", "at least one artifact is required")
	}

	seen := make(map[string]int, len(f.Artifacts))
	m.Artifacts = make([]Artifact, 0, len(f.Artifacts))

	for i, a := range f.Artifacts {
		field := fmt.Sprintf("artifacts[%d]", i)

		switch {
		case a.ID == "":
			return l.errf(field+".id", "is required")
		case !idPattern.MatchString(a.ID):
			// Ids become filenames and DependencyTrack project names.
			return l.errf(field+".id", "%q does not match %s", a.ID, idPattern)
		}
		if first, dup := seen[a.ID]; dup {
			return l.errf(field+".id", "%q is already used by artifacts[%d]", a.ID, first)
		}
		seen[a.ID] = i

		if a.SBOM == "" {
			return l.errf(field+".sbom", "is required: a glob relative to the manifest directory")
		}

		out := Artifact{ID: a.ID, SBOM: a.SBOM}

		if a.Subject != nil {
			// Both halves are required: the override replaces
			// metadata.component.name and .version together, and a
			// half-specified subject would silently keep the generator's
			// value for the other half (§4.3d).
			if a.Subject.Name == "" {
				return l.errf(field+".subject.name", "is required when subject is given")
			}
			if a.Subject.Version == "" {
				return l.errf(field+".subject.version", "is required when subject is given")
			}
			out.Subject = &Subject{Name: a.Subject.Name, Version: a.Subject.Version}
		}

		for j := range a.Transforms {
			spec, err := l.transform(fmt.Sprintf("%s.transforms[%d]", field, j), &a.Transforms[j])
			if err != nil {
				return err
			}
			out.Transforms = append(out.Transforms, spec)
		}

		m.Artifacts = append(m.Artifacts, out)
	}
	return nil
}

func (l loader) output(f *fileSection, m *Manifest) error {
	m.Output.SpecVersionFloor = DefaultSpecVersionFloor
	if f.Output == nil || f.Output.SpecVersionFloor == nil {
		return nil
	}

	floor := *f.Output.SpecVersionFloor
	if !supportedFloor(floor) {
		return l.errf("output.specVersionFloor", "%q is not supported, allowed values are %s",
			floor, strings.Join(sbom.SupportedFloors, " and "))
	}
	m.Output.SpecVersionFloor = floor
	return nil
}

func (l loader) gate(f *fileSection, m *Manifest) error {
	if f.Gate == nil || f.Gate.Require == nil {
		m.Gate.Require = DefaultRequire()
		return nil
	}

	// An explicitly empty list is the empty subset (§2): the subject check in
	// §5 step 4 still runs, but no per-component field is required.
	require := *f.Gate.Require
	seen := make(map[string]bool, len(require))
	for _, r := range require {
		switch r {
		case RequireName, RequireVersion, RequirePURL:
		default:
			return l.errf("gate.require", "%q is not a gate field, allowed values are %s, %s and %s",
				r, RequireName, RequireVersion, RequirePURL)
		}
		if seen[r] {
			return l.errf("gate.require", "%q is listed more than once", r)
		}
		seen[r] = true
	}
	m.Gate.Require = append([]string(nil), require...)
	return nil
}

func supportedFloor(v string) bool {
	for _, f := range sbom.SupportedFloors {
		if f == v {
			return true
		}
	}
	return false
}

// unknownField matches the go-yaml phrasing for a KnownFields violation, which
// names an internal Go type the manifest author has never heard of.
var unknownField = regexp.MustCompile(`field (\S+) not found in type \S+`)

// yamlError turns a decode failure into a message about the manifest rather
// than about this package's structs.
func (l loader) yamlError(err error) error {
	var typeErr *yaml.TypeError
	if errors.As(err, &typeErr) {
		msgs := make([]string, 0, len(typeErr.Errors))
		for _, e := range typeErr.Errors {
			msgs = append(msgs, unknownField.ReplaceAllString(e, `unknown field "$1"`))
		}
		return l.errf("", "%s", strings.Join(msgs, "; "))
	}
	return l.errf("", "%s", strings.TrimPrefix(err.Error(), "yaml: "))
}

// describe renders a node for an error message: its scalar text when it has
// one, otherwise the shape it turned out to be.
func describe(n *yaml.Node) string {
	if n.Kind == yaml.ScalarNode {
		return fmt.Sprintf("%q", n.Value)
	}
	switch n.Kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a list"
	default:
		return "an unexpected value"
	}
}
