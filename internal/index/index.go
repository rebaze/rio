// Package index models and writes index.json, the handoff object §4.2 defines.
//
// The shape is a contract, not an implementation detail: the DependencyTrack
// upload script reads it today and rio record will read it tomorrow, so field
// names and types here are load bearing (§9c). Two rules follow from that and
// are enforced rather than hoped for:
//
//   - every array is an array. A nil Go slice serializes as null, and a
//     consumer iterating it breaks on a run that happened to have nothing to
//     report.
//   - no timestamps, anywhere. The index digest is referenced elsewhere and a
//     digest that changes between identical runs is worthless (§7).
package index

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/rebaze/rio/internal/sbom"
)

// SchemaVersion is the version of the index format itself. It is present from
// the first release so a later reader can tell what it is holding (§9c).
const SchemaVersion = 1

// ToolName is the value of tool.name.
const ToolName = "rio"

// FileName is the index's fixed name inside the output directory (§4.1).
const FileName = "index.json"

// Index is the whole of index.json.
type Index struct {
	SchemaVersion int        `json:"schemaVersion"`
	Tool          Tool       `json:"tool"`
	Manifest      FileRef    `json:"manifest"`
	Artifacts     []Artifact `json:"artifacts"`
}

// Tool identifies the rio build that produced the index.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// FileRef is a file rio read or wrote, by relative path and content digest.
//
// Path is relative: to the manifest's directory for inputs, to the index
// file's own directory for outputs (§4.2, §7). SHA256 is lowercase hex over
// the bytes on disk, computed after writing.
type FileRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// SpecVersions records the CycloneDX version in and out, so a reader can see
// whether uplift happened without diffing the documents.
type SpecVersions struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

// TransformResult is one transform's outcome on one artifact.
type TransformResult struct {
	ID       string `json:"id"`
	Applied  int    `json:"applied"`
	Unmapped int    `json:"unmapped"`
	// Skipped counts components the transform's scope filter excluded. It is a
	// third outcome, distinct from unmapped: out of scope is not a miss (§6.2).
	Skipped int `json:"skipped"`
}

// GateFinding is one gate failure (§5 step 4).
type GateFinding struct {
	// Subject is true when the failure is the document's own subject,
	// metadata.component, rather than a component in the list. A subject
	// failure fails the artifact regardless of gate.require.
	Subject bool `json:"subject,omitempty"`
	// Component identifies the offending component, by purl where it has one
	// and by name otherwise. Empty on a subject finding.
	Component string `json:"component,omitempty"`
	// Missing lists the required fields that were absent or empty.
	Missing []string `json:"missing"`
}

// Artifact is one manifest artifact's row in the index. ID is the stable key
// (§4.2).
type Artifact struct {
	ID              string            `json:"id"`
	Input           FileRef           `json:"input"`
	Output          FileRef           `json:"output"`
	SpecVersion     SpecVersions      `json:"specVersion"`
	SchemaValidated bool              `json:"schemaValidated"`
	Components      int               `json:"components"`
	Transforms      []TransformResult `json:"transforms"`
	Gate            Gate              `json:"gate"`
	GateFindings    []GateFinding     `json:"gateFindings"`

	// IntegrityFindings are dangling dependency references: reported, never
	// repaired, never fatal (§5 step 2b).
	//
	// Unlike gateFindings this key is omitted when empty rather than emitted
	// as []. A clean run then produces exactly the document §4.2 shows, which
	// carries no integrityFindings key at all, and the key's presence is
	// itself the signal that something needs looking at.
	IntegrityFindings []sbom.IntegrityFinding `json:"integrityFindings,omitempty"`
}

// Gate is an artifact's gate result. Exactly two values are legal (§4.2).
type Gate string

const (
	GateOK   Gate = "ok"
	GateFail Gate = "fail"
)

// Valid reports whether g is one of the two contract values. The zero value is
// not: an artifact whose gate was never set must not serialize as "".
func (g Gate) Valid() bool { return g == GateOK || g == GateFail }

// MarshalJSON refuses anything but ok and fail, so an unset or invented gate
// fails the run instead of writing a value no consumer can interpret. Under
// --gate warn the result is still recorded as fail here; only the exit code
// changes (§5 step 4).
func (g Gate) MarshalJSON() ([]byte, error) {
	if !g.Valid() {
		return nil, fmt.Errorf("gate is %q, want %q or %q", string(g), GateOK, GateFail)
	}
	return json.Marshal(string(g))
}

// UnmarshalJSON rejects unknown gate values. rio record will read this file
// and must not silently treat an unrecognised gate as a pass.
func (g *Gate) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed := Gate(s)
	if !parsed.Valid() {
		return fmt.Errorf("gate is %q, want %q or %q", s, GateOK, GateFail)
	}
	*g = parsed
	return nil
}

// New starts an index for a run, with the format and tool fields already
// correct so a caller cannot forget them.
func New(toolVersion string, manifest FileRef) *Index {
	return &Index{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: ToolName, Version: toolVersion},
		Manifest:      manifest,
		Artifacts:     []Artifact{},
	}
}

// Add appends an artifact row, in the order the artifacts were processed. The
// manifest's order is the index's order; nothing is sorted.
func (idx *Index) Add(a Artifact) { idx.Artifacts = append(idx.Artifacts, a) }

// Marshal serializes the index. The result is byte identical across runs and
// platforms for the same input, and ends in a single newline.
//
// Serialization normalizes a copy, never the caller's index: nil slices become
// empty ones and a zero schemaVersion becomes the current one, since that
// field is a constant of the format rather than caller data.
func Marshal(idx *Index) ([]byte, error) {
	// Checked up front so the error can name the offending artifact; a
	// MarshalJSON error raised mid-encode cannot, and "gate is \"\"" with no
	// id is not a message anyone can act on.
	if err := idx.Validate(); err != nil {
		return nil, err
	}
	normalized := normalize(idx)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// Escaping off so purls in gate and integrity findings stay readable, and
	// the two-space indent matches the SBOMs rio writes beside this file.
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(normalized); err != nil {
		return nil, fmt.Errorf("serializing %s: %w", FileName, err)
	}
	return buf.Bytes(), nil
}

// normalize returns a deep enough copy of idx for serialization: every slice
// the format promises as an array is non-nil, and identity fields are filled
// in. Nothing reachable from the caller's index is mutated.
func normalize(idx *Index) *Index {
	out := *idx

	if out.SchemaVersion == 0 {
		out.SchemaVersion = SchemaVersion
	}
	if out.Tool.Name == "" {
		out.Tool.Name = ToolName
	}

	out.Artifacts = make([]Artifact, len(idx.Artifacts))
	copy(out.Artifacts, idx.Artifacts)

	for i := range out.Artifacts {
		a := &out.Artifacts[i]

		if a.Transforms == nil {
			a.Transforms = []TransformResult{}
		}

		findings := make([]GateFinding, len(a.GateFindings))
		copy(findings, a.GateFindings)
		for j := range findings {
			if findings[j].Missing == nil {
				findings[j].Missing = []string{}
			}
		}
		a.GateFindings = findings
	}
	return &out
}

// Validate reports the first structural problem that would make the index
// unusable to a consumer. Marshal enforces the gate values on its own; this
// exists so a caller can fail before writing any file.
func (idx *Index) Validate() error {
	for _, a := range idx.Artifacts {
		if a.ID == "" {
			return fmt.Errorf("artifact with no id")
		}
		if !a.Gate.Valid() {
			return fmt.Errorf("artifact %q: gate is %q, want %q or %q", a.ID, string(a.Gate), GateOK, GateFail)
		}
	}
	return nil
}
