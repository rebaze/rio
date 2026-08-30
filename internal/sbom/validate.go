package sbom

import (
	"bytes"
	"embed"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// CycloneDX publishes no JSON schema before 1.2; 1.0 and 1.1 are XML only.
//
//go:embed schemas/*.json
var schemaFS embed.FS

const schemaBaseURL = "http://cyclonedx.org/schema/"

// HighestSchemaVersion is the newest spec version rio can validate. A document
// above it passes through with validation skipped (§3, §5 step 2b).
const HighestSchemaVersion = "1.6"

// ErrNoSchema reports that no embedded schema covers a spec version.
type ErrNoSchema struct{ SpecVersion string }

func (e *ErrNoSchema) Error() string {
	return fmt.Sprintf("no embedded schema for CycloneDX %s", e.SpecVersion)
}

// ValidationError lists every schema violation found in one document.
type ValidationError struct {
	SpecVersion string
	Violations  []Violation
}

// Violation is a single schema violation, located by JSON pointer.
type Violation struct {
	// Path is the JSON pointer into the instance, e.g. "/components/3/purl".
	Path    string
	Message string
}

func (e *ValidationError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d schema violation(s) against CycloneDX %s", len(e.Violations), e.SpecVersion)
	for _, v := range e.Violations {
		p := v.Path
		if p == "" {
			p = "/"
		}
		fmt.Fprintf(&b, "\n  %s: %s", p, v.Message)
	}
	return b.String()
}

var (
	schemaOnce  sync.Once
	schemaCache map[string]*jsonschema.Schema
	schemaErr   error
)

// SchemaAvailable reports whether an embedded schema covers a spec version.
func SchemaAvailable(specVersion string) bool {
	if err := loadSchemas(); err != nil {
		return false
	}
	_, ok := schemaCache[specVersion]
	return ok
}

func loadSchemas() error {
	schemaOnce.Do(func() {
		entries, err := schemaFS.ReadDir("schemas")
		if err != nil {
			schemaErr = fmt.Errorf("reading embedded schemas: %w", err)
			return
		}

		// Every schema is registered under its cyclonedx.org URL so the
		// relative $refs between them (spdx.schema.json, jsf-0.82.schema.json)
		// resolve locally. Nothing here touches the network.
		compiler := jsonschema.NewCompiler()
		var bomFiles []string
		for _, entry := range entries {
			name := entry.Name()
			data, err := schemaFS.ReadFile(path.Join("schemas", name))
			if err != nil {
				schemaErr = fmt.Errorf("reading embedded schema %s: %w", name, err)
				return
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
			if err != nil {
				schemaErr = fmt.Errorf("parsing embedded schema %s: %w", name, err)
				return
			}
			if err := compiler.AddResource(schemaBaseURL+name, doc); err != nil {
				schemaErr = fmt.Errorf("registering embedded schema %s: %w", name, err)
				return
			}
			if strings.HasPrefix(name, "bom-") {
				bomFiles = append(bomFiles, name)
			}
		}

		sort.Strings(bomFiles)
		schemaCache = map[string]*jsonschema.Schema{}
		for _, name := range bomFiles {
			version := strings.TrimSuffix(strings.TrimPrefix(name, "bom-"), ".schema.json")
			sch, err := compiler.Compile(schemaBaseURL + name)
			if err != nil {
				schemaErr = fmt.Errorf("compiling embedded schema %s: %w", name, err)
				return
			}
			schemaCache[version] = sch
		}
	})
	return schemaErr
}

// Validate checks CycloneDX JSON against the embedded schema for specVersion.
//
// It returns *ErrNoSchema when no embedded schema covers the version, which
// callers treat as "skip validation and record schemaValidated: false" rather
// than as a failure (§3).
func Validate(data []byte, specVersion string) error {
	if err := loadSchemas(); err != nil {
		return err
	}
	sch, ok := schemaCache[specVersion]
	if !ok {
		return &ErrNoSchema{SpecVersion: specVersion}
	}

	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("not valid JSON: %w", err)
	}

	if err := sch.Validate(instance); err != nil {
		var verr *jsonschema.ValidationError
		if ok := asValidationError(err, &verr); ok {
			return &ValidationError{SpecVersion: specVersion, Violations: flatten(verr)}
		}
		return err
	}
	return nil
}

// ValidateSelf validates the document as it currently stands, at its own
// declared spec version.
func (d *Document) ValidateSelf() error {
	data, err := d.Bytes()
	if err != nil {
		return err
	}
	return Validate(data, d.specVersion)
}

func asValidationError(err error, target **jsonschema.ValidationError) bool {
	v, ok := err.(*jsonschema.ValidationError)
	if ok {
		*target = v
	}
	return ok
}

// flatten reduces the validation error tree to its leaves, which carry the
// specific violations rather than the "does not match schema" roll-ups.
func flatten(e *jsonschema.ValidationError) []Violation {
	var out []Violation
	var walk func(jsonschema.OutputUnit)
	walk = func(node jsonschema.OutputUnit) {
		if len(node.Errors) == 0 {
			msg := ""
			if node.Error != nil {
				msg = node.Error.String()
			}
			out = append(out, Violation{Path: node.InstanceLocation, Message: msg})
			return
		}
		for _, c := range node.Errors {
			walk(c)
		}
	}
	walk(*e.DetailedOutput())

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Message < out[j].Message
	})

	// Cap the report: a badly broken document produces thousands of leaves,
	// and the first handful is what a human acts on.
	const maxViolations = 25
	if len(out) > maxViolations {
		extra := len(out) - maxViolations
		out = append(out[:maxViolations:maxViolations], Violation{
			Message: fmt.Sprintf("... and %d more violation(s)", extra),
		})
	}
	return out
}
