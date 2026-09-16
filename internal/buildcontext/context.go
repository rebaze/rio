// Package buildcontext reads producer-supplied build context assertions.
package buildcontext

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Binding connects one manifest artifact to a build context file.
type Binding struct {
	File    string   `yaml:"file" json:"file"`
	Require []string `yaml:"require" json:"require"`
	Replace []string `yaml:"replace" json:"replace"`
}

// FileRef identifies the exact context bytes read for a run.
type FileRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Digest identifies a content-addressed input in a context document.
type Digest struct {
	SHA256 string `json:"sha256"`
}

// SBOM is the original input SBOM digest carried by an artifact entry.
type SBOM = Digest

// Artifact is one producer assertion from a context file.
type Artifact struct {
	ID        string  `json:"id"`
	SBOM      Digest  `json:"sbom"`
	Source    *Source `json:"source,omitempty"`
	Build     *Build  `json:"build,omitempty"`
	Generator *Tool   `json:"generator,omitempty"`
	Lifecycle *string `json:"lifecycle,omitempty"`
}

// Source describes the source assertion associated with a product artifact.
type Source struct {
	Repository   *string `json:"repository,omitempty"`
	Revision     *string `json:"revision,omitempty"`
	Subdirectory *string `json:"subdirectory,omitempty"`
	Ref          *string `json:"ref,omitempty"`
	Workspace    *string `json:"workspace,omitempty"`
}

// Build describes the system that produced a product artifact.
type Build struct {
	URL       *string `json:"url,omitempty"`
	ID        *string `json:"id,omitempty"`
	Timestamp *string `json:"timestamp,omitempty"`
	System    *Tool   `json:"system,omitempty"`
}

// Tool records the name and optional version of a producer tool or system.
type Tool struct {
	Name    *string `json:"name,omitempty"`
	Version *string `json:"version,omitempty"`
}

// File is an immutable, validated context file snapshot.
type File struct {
	ref       FileRef
	artifacts []Artifact
}

// Field is one flattened effective assertion, with its source JSON pointer.
type Field struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Selector  string `json:"selector"`
	Defaulted bool   `json:"defaulted"`
}

// Resolved is a selected context entry, validated for a manifest artifact.
type Resolved struct {
	File      FileRef  `json:"file"`
	Selector  string   `json:"selector"`
	Artifact  Artifact `json:"artifact"`
	Defaulted []string `json:"defaulted"`
	Fields    []Field  `json:"fields"`
	Replace   []string `json:"replace"`
}

var knownFields = map[string]bool{
	"source.repository": true, "source.revision": true, "source.subdirectory": true,
	"source.ref": true, "source.workspace": true, "build.url": true,
	"build.id": true, "build.timestamp": true, "build.system.name": true,
	"build.system.version": true, "generator.name": true, "generator.version": true,
	"lifecycle": true,
}

// ValidateBinding validates the manifest-side policy. A nil binding means no
// context declaration and is valid.
func ValidateBinding(binding *Binding) error {
	if binding == nil {
		return nil
	}
	if invalidString(binding.File) {
		return errors.New("context.file must be a nonblank string")
	}
	for _, part := range []struct {
		name string
		keys []string
	}{{"require", binding.Require}, {"replace", binding.Replace}} {
		seen := map[string]bool{}
		for _, key := range part.keys {
			if !knownFields[key] {
				return fmt.Errorf("context.%s: %q is not a known context field", part.name, key)
			}
			if part.name == "replace" && key == "lifecycle" {
				return errors.New("context.replace: lifecycle cannot be replaced")
			}
			if seen[key] {
				return fmt.Errorf("context.%s: %q is listed more than once", part.name, key)
			}
			seen[key] = true
		}
	}
	return nil
}

// Read reads a context file once, parses it strictly, and validates all
// entries. File paths resolve relative to baseDir.
func Read(baseDir, file string) (*File, error) {
	if invalidString(file) {
		return nil, errors.New("context.file must be a nonblank string")
	}
	resolved := file
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(baseDir, resolved)
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("read context file %s: %w", file, err)
	}
	root, err := decodeStrict(data)
	if err != nil {
		return nil, fmt.Errorf("context file %s: %w", file, err)
	}
	artifacts, err := parseDocument(root)
	if err != nil {
		return nil, fmt.Errorf("context file %s: %w", file, err)
	}
	sum := sha256.Sum256(data)
	rel, err := filepath.Rel(baseDir, resolved)
	if err != nil {
		rel = resolved
	}
	return &File{ref: FileRef{Path: filepath.ToSlash(rel), SHA256: hex.EncodeToString(sum[:])}, artifacts: artifacts}, nil
}

// Resolve selects an entry by manifest artifact ID, checks its original input
// digest, and applies the manifest's require policy without mutating File.
func (f *File) Resolve(artifactID, inputSHA string, binding Binding) (*Resolved, error) {
	if f == nil {
		return nil, errors.New("context file is nil")
	}
	if err := ValidateBinding(&binding); err != nil {
		return nil, err
	}
	var selected *Artifact
	index := -1
	for i := range f.artifacts {
		if f.artifacts[i].ID == artifactID {
			selected, index = &f.artifacts[i], i
			break
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("context has no artifact with id %q", artifactID)
	}
	if selected.SBOM.SHA256 != inputSHA {
		return nil, fmt.Errorf("context artifact %q sbom.sha256 does not match the original input SBOM", artifactID)
	}
	artifact := cloneArtifact(*selected)
	workspaceDefaulted := artifact.Source != nil && artifact.Source.Workspace == nil
	if workspaceDefaulted {
		unknown := "unknown"
		artifact.Source.Workspace = &unknown
	}
	fields, defaulted := flatten(artifact, index, workspaceDefaulted)
	present := map[string]bool{}
	for _, field := range fields {
		if !field.Defaulted {
			present[field.Name] = true
		}
	}
	for _, required := range binding.Require {
		if !present[required] {
			return nil, fmt.Errorf("context artifact %q requires explicitly supplied %s", artifactID, required)
		}
	}
	return &Resolved{
		File: f.ref, Selector: fmt.Sprintf("/artifacts/%d", index), Artifact: artifact,
		Defaulted: append([]string(nil), defaulted...), Fields: append([]Field(nil), fields...),
		Replace: append([]string(nil), binding.Replace...),
	}, nil
}

func flatten(a Artifact, index int, workspaceDefaulted bool) ([]Field, []string) {
	prefix := fmt.Sprintf("/artifacts/%d", index)
	fields := make([]Field, 0, len(knownFields))
	add := func(name string, value *string, selector string) {
		if value != nil {
			fields = append(fields, Field{Name: name, Value: *value, Selector: selector})
		}
	}
	if a.Source != nil {
		add("source.repository", a.Source.Repository, prefix+"/source/repository")
		add("source.revision", a.Source.Revision, prefix+"/source/revision")
		add("source.subdirectory", a.Source.Subdirectory, prefix+"/source/subdirectory")
		add("source.ref", a.Source.Ref, prefix+"/source/ref")
		if workspaceDefaulted {
			fields = append(fields, Field{Name: "source.workspace", Value: *a.Source.Workspace, Selector: prefix + "/source", Defaulted: true})
		} else {
			add("source.workspace", a.Source.Workspace, prefix+"/source/workspace")
		}
	}
	if a.Build != nil {
		add("build.url", a.Build.URL, prefix+"/build/url")
		add("build.id", a.Build.ID, prefix+"/build/id")
		add("build.timestamp", a.Build.Timestamp, prefix+"/build/timestamp")
		if a.Build.System != nil {
			add("build.system.name", a.Build.System.Name, prefix+"/build/system/name")
			add("build.system.version", a.Build.System.Version, prefix+"/build/system/version")
		}
	}
	if a.Generator != nil {
		add("generator.name", a.Generator.Name, prefix+"/generator/name")
		add("generator.version", a.Generator.Version, prefix+"/generator/version")
	}
	add("lifecycle", a.Lifecycle, prefix+"/lifecycle")
	sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
	defaulted := make([]string, 0, 1)
	for _, field := range fields {
		if field.Defaulted {
			defaulted = append(defaulted, field.Name)
		}
	}
	return fields, defaulted
}

func cloneArtifact(in Artifact) Artifact {
	out := in
	cloneString := func(v *string) *string {
		if v == nil {
			return nil
		}
		x := *v
		return &x
	}
	if in.Source != nil {
		out.Source = &Source{cloneString(in.Source.Repository), cloneString(in.Source.Revision), cloneString(in.Source.Subdirectory), cloneString(in.Source.Ref), cloneString(in.Source.Workspace)}
	}
	if in.Build != nil {
		out.Build = &Build{URL: cloneString(in.Build.URL), ID: cloneString(in.Build.ID), Timestamp: cloneString(in.Build.Timestamp)}
		if in.Build.System != nil {
			out.Build.System = &Tool{Name: cloneString(in.Build.System.Name), Version: cloneString(in.Build.System.Version)}
		}
	}
	if in.Generator != nil {
		out.Generator = &Tool{Name: cloneString(in.Generator.Name), Version: cloneString(in.Generator.Version)}
	}
	out.Lifecycle = cloneString(in.Lifecycle)
	return out
}

func decodeStrict(data []byte) (any, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	value, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("trailing JSON document")
		}
		return nil, fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return value, nil
}

// DecodeStrict parses a single JSON value, rejecting duplicate keys at every
// depth. It also serves validation of previously owned context records.
func DecodeStrict(data []byte) (any, error) { return decodeStrict(data) }

func decodeValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch v := token.(type) {
	case json.Delim:
		switch v {
		case '{':
			out := map[string]any{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("object key must be a string")
				}
				if _, exists := out[key]; exists {
					return nil, fmt.Errorf("duplicate key %q", key)
				}
				value, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				out[key] = value
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return out, nil
		case '[':
			var out []any
			for dec.More() {
				value, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				out = append(out, value)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return out, nil
		}
	}
	return token, nil
}

func parseDocument(value any) ([]Artifact, error) {
	root, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("document must be an object")
	}
	if err := only(root, "contextVersion", "artifacts"); err != nil {
		return nil, err
	}
	if version, ok := root["contextVersion"].(json.Number); !ok || version.String() != "1" {
		return nil, errors.New("contextVersion must be integer 1")
	}
	raw, ok := root["artifacts"].([]any)
	if !ok || len(raw) == 0 {
		return nil, errors.New("artifacts must be a nonempty array")
	}
	seen := map[string]bool{}
	artifacts := make([]Artifact, 0, len(raw))
	for i, item := range raw {
		artifact, err := parseArtifact(item, fmt.Sprintf("artifacts[%d]", i))
		if err != nil {
			return nil, err
		}
		if seen[artifact.ID] {
			return nil, fmt.Errorf("artifacts[%d].id duplicates artifact id %q", i, artifact.ID)
		}
		seen[artifact.ID] = true
		artifacts = append(artifacts, artifact)
	}
	return artifacts, nil
}

func parseArtifact(value any, field string) (Artifact, error) {
	m, ok := value.(map[string]any)
	if !ok {
		return Artifact{}, fmt.Errorf("%s must be an object", field)
	}
	if err := only(m, "id", "sbom", "source", "build", "generator", "lifecycle"); err != nil {
		return Artifact{}, err
	}
	id, err := requiredString(m, "id", field)
	if err != nil {
		return Artifact{}, err
	}
	sbomValue, ok := m["sbom"]
	if !ok {
		return Artifact{}, fmt.Errorf("%s.sbom is required", field)
	}
	sbomMap, ok := sbomValue.(map[string]any)
	if !ok {
		return Artifact{}, fmt.Errorf("%s.sbom must be an object", field)
	}
	if err := only(sbomMap, "sha256"); err != nil {
		return Artifact{}, err
	}
	digest, err := requiredString(sbomMap, "sha256", field+".sbom")
	if err != nil {
		return Artifact{}, err
	}
	if !lowerHex(digest, 64) {
		return Artifact{}, fmt.Errorf("%s.sbom.sha256 must be 64 lowercase hexadecimal characters", field)
	}
	a := Artifact{ID: id, SBOM: Digest{SHA256: digest}}
	if raw, present := m["source"]; present {
		source, err := parseSource(raw, field+".source")
		if err != nil {
			return Artifact{}, err
		}
		a.Source = source
	}
	if raw, present := m["build"]; present {
		build, err := parseBuild(raw, field+".build")
		if err != nil {
			return Artifact{}, err
		}
		a.Build = build
	}
	if raw, present := m["generator"]; present {
		tool, err := parseTool(raw, field+".generator")
		if err != nil {
			return Artifact{}, err
		}
		a.Generator = tool
	}
	if raw, present := m["lifecycle"]; present {
		lifecycle, err := stringValue(raw, field+".lifecycle")
		if err != nil {
			return Artifact{}, err
		}
		if !knownLifecycle(lifecycle) {
			return Artifact{}, fmt.Errorf("%s.lifecycle is not a supported CycloneDX lifecycle", field)
		}
		a.Lifecycle = &lifecycle
	}
	return a, nil
}

// ParseEffective validates a previously recorded effective artifact without
// opening a file. It uses the same strict shape and value rules as input entries.
func ParseEffective(data []byte) (Artifact, error) {
	value, err := decodeStrict(data)
	if err != nil {
		return Artifact{}, err
	}
	return parseArtifact(value, "effective")
}

func parseSource(value any, field string) (*Source, error) {
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", field)
	}
	if err := only(m, "repository", "revision", "subdirectory", "ref", "workspace"); err != nil {
		return nil, err
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("%s must not be empty", field)
	}
	s := &Source{}
	var err error
	if s.Repository, err = optionalString(m, "repository", field); err != nil {
		return nil, err
	}
	if s.Repository != nil && !validURL(*s.Repository) {
		return nil, fmt.Errorf("%s.repository must be an absolute HTTP(S) URL without credentials", field)
	}
	if s.Revision, err = optionalString(m, "revision", field); err != nil {
		return nil, err
	}
	if s.Revision != nil && !(lowerHex(*s.Revision, 40) || lowerHex(*s.Revision, 64)) {
		return nil, fmt.Errorf("%s.revision must be 40 or 64 lowercase hexadecimal characters", field)
	}
	if s.Subdirectory, err = optionalString(m, "subdirectory", field); err != nil {
		return nil, err
	}
	if s.Subdirectory != nil && !validSubdirectory(*s.Subdirectory) {
		return nil, fmt.Errorf("%s.subdirectory must be a canonical relative POSIX directory", field)
	}
	if s.Ref, err = optionalString(m, "ref", field); err != nil {
		return nil, err
	}
	if s.Workspace, err = optionalString(m, "workspace", field); err != nil {
		return nil, err
	}
	if s.Workspace != nil && *s.Workspace != "clean" && *s.Workspace != "dirty" && *s.Workspace != "unknown" {
		return nil, fmt.Errorf("%s.workspace must be clean, dirty, or unknown", field)
	}
	return s, nil
}

func parseBuild(value any, field string) (*Build, error) {
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", field)
	}
	if err := only(m, "url", "id", "timestamp", "system"); err != nil {
		return nil, err
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("%s must not be empty", field)
	}
	b := &Build{}
	var err error
	if b.URL, err = optionalString(m, "url", field); err != nil {
		return nil, err
	}
	if b.URL != nil && !validURL(*b.URL) {
		return nil, fmt.Errorf("%s.url must be an absolute HTTP(S) URL without credentials", field)
	}
	if b.ID, err = optionalString(m, "id", field); err != nil {
		return nil, err
	}
	if b.Timestamp, err = optionalString(m, "timestamp", field); err != nil {
		return nil, err
	}
	if b.Timestamp != nil {
		if _, err := timeRFC3339(*b.Timestamp); err != nil {
			return nil, fmt.Errorf("%s.timestamp must be RFC3339", field)
		}
	}
	if raw, present := m["system"]; present {
		b.System, err = parseTool(raw, field+".system")
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

func parseTool(value any, field string) (*Tool, error) {
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", field)
	}
	if err := only(m, "name", "version"); err != nil {
		return nil, err
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("%s must not be empty", field)
	}
	name, err := requiredString(m, "name", field)
	if err != nil {
		return nil, err
	}
	version, err := optionalString(m, "version", field)
	if err != nil {
		return nil, err
	}
	return &Tool{Name: &name, Version: version}, nil
}

func only(m map[string]any, allowed ...string) error {
	set := map[string]bool{}
	for _, key := range allowed {
		set[key] = true
	}
	for key := range m {
		if !set[key] {
			return fmt.Errorf("unknown key %q", key)
		}
	}
	return nil
}
func requiredString(m map[string]any, key, field string) (string, error) {
	value, ok := m[key]
	if !ok {
		return "", fmt.Errorf("%s.%s is required", field, key)
	}
	return stringValue(value, field+"."+key)
}
func optionalString(m map[string]any, key, field string) (*string, error) {
	value, ok := m[key]
	if !ok {
		return nil, nil
	}
	s, err := stringValue(value, field+"."+key)
	if err != nil {
		return nil, err
	}
	return &s, nil
}
func stringValue(value any, field string) (string, error) {
	s, ok := value.(string)
	if !ok || invalidString(s) {
		return "", fmt.Errorf("%s must be a nonblank string", field)
	}
	return s, nil
}
func invalidString(s string) bool {
	if strings.TrimSpace(s) == "" || strings.TrimSpace(s) != s {
		return true
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
func validURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && !invalidString(value) && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.User == nil && !u.ForceQuery && u.RawQuery == "" && u.Fragment == "" && !strings.Contains(value, "#")
}
func validSubdirectory(value string) bool {
	if invalidString(value) || strings.Contains(value, "\\") || path.IsAbs(value) {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
func knownLifecycle(value string) bool {
	switch value {
	case "design", "pre-build", "build", "post-build", "operations", "discovery", "decommission":
		return true
	}
	return false
}
func timeRFC3339(value string) (time.Time, error) { return time.Parse(time.RFC3339, value) }
