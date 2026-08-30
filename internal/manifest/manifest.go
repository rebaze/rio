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
	"strconv"
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

	l := loader{path: path, src: data}

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
		if emptyDocument(&extra) {
			// A trailing "---" with nothing after it is the common case, and
			// calling that "more than one document" describes the file badly.
			return nil, l.errf("", `a "---" marker starts a second, empty document, rio reads exactly one: remove the marker`)
		}
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

// loader carries the manifest path so every message can name it, and the
// source bytes so a decode failure can be traced back to the key that caused
// it (§10).
type loader struct {
	path string
	src  []byte
}

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
	// The node must be an integer, not merely something that decodes into one:
	// yaml reads 1.0 as a float and "1" as a string, and letting either stand
	// for 1 would make rio's compatibility lever (§9) depend on how it was
	// quoted.
	if f.Version.Tag != intTag {
		return l.errf("version", "must be the integer %d, got %s", Version, describe(&f.Version))
	}
	var v int
	if err := f.Version.Decode(&v); err != nil {
		// An integer too large for an int lands here.
		return l.errf("version", "must be the integer %d, got %s", Version, describe(&f.Version))
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

// The YAML tags this package reasons about. yaml.v3 keeps them unexported.
const (
	strTag   = "!!str"
	intTag   = "!!int"
	floatTag = "!!float"
	boolTag  = "!!bool"
	nullTag  = "!!null"
	mapTag   = "!!map"
	seqTag   = "!!seq"
	mergeTag = "!!merge"
)

// go-yaml reports a decode failure in terms of the Go type it was decoding
// into. These match its two phrasings so both can be rewritten to name the
// manifest key the author actually wrote (§10).
var (
	// The key is matched lazily and may be empty, because a YAML key can
	// contain spaces ("my key": 1) or be the empty string.
	unknownKey = regexp.MustCompile("^line ([0-9]+): field (.*?) not found in type (\\S+)$")
	// For example: line 5: cannot unmarshal !!str `thing` into manifest.subjectSection
	typeMismatch = regexp.MustCompile("^line ([0-9]+): cannot unmarshal (\\S+)(?: `(.*)`)? into (\\S+)$")
)

// yamlTargets maps every Go type reachable from fileSection to the manifest
// keys that hold it and the shape those keys must have. The types are this
// package's private business; the manifest author only ever wrote the key, so
// that is what a message names (§10).
//
// where is the set of manifest paths a value of that type can sit at, as §2
// defines them. It is what tells the id in artifacts[0].id apart from the
// artifacts list itself when both start on the reported line.
var yamlTargets = map[string]struct {
	field string         // named when the source lookup finds nothing
	shape string         // what the author should have written there
	root  bool           // the document itself, which has no key to name
	where *regexp.Regexp // paths that hold a value of this type
}{
	"manifest.fileSection": {shape: "a mapping with version and artifacts", root: true},
	"[]manifest.artifactSection": {field: "artifacts", shape: "a list of artifact entries",
		where: regexp.MustCompile(`^artifacts$`)},
	"manifest.artifactSection": {field: "artifacts[]", shape: "a mapping with id and sbom",
		where: regexp.MustCompile(`^artifacts\[[0-9]+\]$`)},
	"manifest.subjectSection": {field: "subject", shape: "a mapping with name and version",
		where: regexp.MustCompile(`^artifacts\[[0-9]+\]\.subject$`)},
	"manifest.outputSection": {field: "output", shape: "a mapping",
		where: regexp.MustCompile(`^output$`)},
	"manifest.gateSection": {field: "gate", shape: "a mapping",
		where: regexp.MustCompile(`^gate$`)},
	"[]yaml.Node": {field: "transforms", shape: "a list of transforms",
		where: regexp.MustCompile(`^artifacts\[[0-9]+\]\.transforms$`)},
	"[]string": {field: "gate.require", shape: "a list of strings",
		where: regexp.MustCompile(`^gate\.require$`)},
	// The one type several keys share, which is why it names none of them
	// when the lookup below cannot tell which one was meant.
	"string": {shape: "a string", where: regexp.MustCompile(
		`^(artifacts\[[0-9]+\]\.(id|sbom|subject\.(name|version))|output\.specVersionFloor|gate\.require\[[0-9]+\])$`)},
}

// yamlDetail reduces a decode failure to go-yaml's own words, without the
// "yaml:" prefix and the "unmarshal errors:" header it wraps them in.
func yamlDetail(err error) string {
	var typeErr *yaml.TypeError
	if errors.As(err, &typeErr) {
		return strings.Join(typeErr.Errors, "; ")
	}
	return strings.TrimPrefix(err.Error(), "yaml: ")
}

// yamlError turns a decode failure into a message about the manifest rather
// than about this package's structs: it rewrites every message go-yaml
// produced so it names the manifest key and the shape that key must have,
// never an internal Go type (§10).
func (l loader) yamlError(err error) error {
	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) {
		return l.errf("", "%s", yamlDetail(err))
	}
	// The document parsed (a syntax error is not a TypeError), so re-reading it
	// as a node tree is what turns a reported line into a path such as
	// artifacts[0].subject. If it somehow fails, only that detail is lost.
	var doc yaml.Node
	_ = yaml.Unmarshal(l.src, &doc)

	msgs := make([]string, 0, len(typeErr.Errors))
	seen := make(map[string]bool, len(typeErr.Errors))
	for _, e := range typeErr.Errors {
		msg := l.rewrite(e, &doc)
		// go-yaml reports one failure per field, and two fields written on one
		// line can rewrite to the same message. Repeating it adds nothing.
		if seen[msg] {
			continue
		}
		seen[msg] = true
		msgs = append(msgs, msg)
	}
	return l.errf("", "%s", strings.Join(msgs, "; "))
}

// rewrite restates one go-yaml message in the manifest's own vocabulary. doc is
// the manifest source as a node tree, used to name the offending key.
func (l loader) rewrite(msg string, doc *yaml.Node) string {
	if m := unknownKey.FindStringSubmatch(msg); m != nil {
		line, key := m[1], m[2]
		field := yamlTargets[m[3]].field
		if path, ok := mappingPath(doc, atoiOrZero(line), key); ok {
			field = path
		}
		if field == "" {
			return fmt.Sprintf("line %s: unknown key %q", line, key)
		}
		return fmt.Sprintf("%s: line %s: unknown key %q", field, line, key)
	}

	m := typeMismatch.FindStringSubmatch(msg)
	if m == nil {
		// go-yaml's remaining phrasing, a duplicate key, already talks about
		// the manifest and names no Go type.
		return msg
	}
	line, tag, value := m[1], m[2], m[3]
	target, known := yamlTargets[m[4]]
	if !known {
		// Unreachable while yamlTargets covers fileSection; a new field of a
		// new type would land here with go-yaml's own phrasing.
		return msg
	}
	// The reported tag and value are enough to describe the offending value
	// even when it cannot be located in the source.
	got := describe(nodeFor(tag, value))
	if target.root {
		return fmt.Sprintf("line %s: the manifest must be %s, got %s", line, target.shape, got)
	}
	field := target.field
	if path, n, ok := valuePath(doc, target.where, atoiOrZero(line), tag, value); ok {
		field, got = path, describe(n)
	}
	if field == "" {
		return fmt.Sprintf("line %s: must be %s, got %s", line, target.shape, got)
	}
	return fmt.Sprintf("%s: line %s: must be %s, got %s", field, line, target.shape, got)
}

// walk visits the document's root and every value below it, giving each the
// manifest path of the key or index that holds it: artifacts[0].subject rather
// than a line number. Keys are not visited: only values are decode targets.
func walk(n *yaml.Node, path string, fn func(path string, n *yaml.Node)) {
	if n.Kind == yaml.DocumentNode {
		for _, c := range n.Content {
			walk(c, path, fn)
		}
		return
	}
	fn(path, n)
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, value := n.Content[i], n.Content[i+1]
			child := key.Value
			if path != "" {
				child = path + "." + key.Value
			}
			walk(value, child, fn)
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			walk(c, fmt.Sprintf("%s[%d]", path, i), fn)
		}
	}
}

// valuePath finds the value go-yaml refused, by the line, tag and text it
// reported and the paths that can hold its type. A line alone is not enough:
// a block sequence starts on the line of its first entry, and a flow
// collection holds its children on its own line. Two candidates that are both
// legal (artifacts: [{id: [a], sbom: [b]}]) yield nothing rather than a
// message pointing at the wrong one.
func valuePath(doc *yaml.Node, where *regexp.Regexp, line int, tag, value string) (string, *yaml.Node, bool) {
	var found *yaml.Node
	foundPath, matches := "", 0
	walk(doc, "", func(path string, n *yaml.Node) {
		if n.Line != line || n.Tag != tag || !where.MatchString(path) || !valueMatches(n.Value, value) {
			return
		}
		found, foundPath, matches = n, path, matches+1
	})
	if matches != 1 {
		return "", nil, false
	}
	return foundPath, found, true
}

// mappingPath finds the mapping that holds key at line, so an unknown key is
// reported against the section it was written in. The root mapping has the
// empty path, which reads as "no section", exactly what a stray top-level key
// deserves.
func mappingPath(doc *yaml.Node, line int, key string) (string, bool) {
	found := ""
	matches := 0
	walk(doc, "", func(path string, n *yaml.Node) {
		if n.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			if k := n.Content[i]; k.Value == key && k.Line == line {
				found, matches = path, matches+1
			}
		}
	})
	if matches != 1 {
		return "", false
	}
	return found, true
}

// valueMatches compares a node's text with the text go-yaml reported, which
// truncates anything over ten characters to seven and an ellipsis.
func valueMatches(got, reported string) bool {
	if len(reported) == 10 && strings.HasSuffix(reported, "...") {
		return strings.HasPrefix(got, strings.TrimSuffix(reported, "..."))
	}
	return got == reported
}

// atoiOrZero keeps a line number usable in a message even if it does not parse:
// zero matches no node, so the lookup simply finds nothing.
func atoiOrZero(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// nodeFor rebuilds just enough of a node from what go-yaml reported about it
// for describe to render it the same way as a node read from the source.
func nodeFor(tag, value string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value}
	switch tag {
	case mapTag:
		n.Kind = yaml.MappingNode
	case seqTag:
		n.Kind = yaml.SequenceNode
	}
	return n
}

// emptyDocument reports whether a decoded document holds nothing, which is what
// a trailing "---" produces.
func emptyDocument(n *yaml.Node) bool {
	return len(n.Content) == 0 || n.Content[0].Tag == nullTag
}

// describe renders a node for an error message: what it holds and, for a
// scalar, which YAML type it holds it as. The type is part of the value:
// version: "1" and version: 1 differ in nothing else (§9).
func describe(n *yaml.Node) string {
	switch n.Kind {
	case yaml.ScalarNode:
		switch n.Tag {
		case strTag:
			return fmt.Sprintf("the string %q", n.Value)
		case intTag, floatTag:
			return "the number " + n.Value
		case boolTag:
			return "the boolean " + n.Value
		case nullTag:
			return "no value"
		default:
			// A tag rio has no name for, such as !!timestamp.
			return fmt.Sprintf("%q", n.Value)
		}
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a list"
	default:
		// An alias (version: *anchor) is the only kind that reaches here.
		return "an unexpected value"
	}
}
