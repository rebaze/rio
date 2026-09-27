// Package receipt defines the unsigned, source-free snapshot of one Rio invocation.
// Paths and URLs are references only: parsing never opens or follows them.
package receipt

const (
	Kind          = "rio-run-receipt"
	MaxBytes      = 8 << 20
	MaxItems      = 10000
	MaxValueBytes = 1024
)

type Document struct {
	Kind          string            `json:"kind"`
	SchemaVersion int               `json:"schemaVersion"`
	RioVersion    string            `json:"rioVersion"`
	Run           Run               `json:"run"`
	Artifacts     []Artifact        `json:"artifacts,omitempty"`
	Targets       map[string]Target `json:"targets,omitempty"`
	Deliveries    []Delivery        `json:"deliveries,omitempty"`
	Exclusions    []Exclusion       `json:"exclusions,omitempty"`
	Exceptions    []string          `json:"exceptions,omitempty"`
}
type Run struct {
	ID         string            `json:"id"`
	Operation  string            `json:"operation"`
	StartedAt  string            `json:"startedAt"`
	FinishedAt string            `json:"finishedAt,omitempty"`
	Outcome    string            `json:"outcome"`
	Stages     map[string]string `json:"stages"`
	Overrides  map[string]string `json:"overrides,omitempty"`
	Prior      *Prior            `json:"prior,omitempty"`
}
type Prior struct {
	RunID     string `json:"runId,omitempty"`
	AttemptID string `json:"attemptId,omitempty"`
	SHA256    string `json:"sha256"`
}

// Bytes either identifies bytes directly, or references this receipt's output.
// Size is the byte count, including when the bytes differ from the input SBOM.
type Bytes struct {
	ArtifactOutput string `json:"artifactOutput,omitempty"`
	Path           string `json:"path,omitempty"`
	SHA256         string `json:"sha256,omitempty"`
	Size           int64  `json:"size,omitempty"`
	MediaType      string `json:"mediaType,omitempty"`
	Role           string `json:"role,omitempty"`
	Transformation string `json:"transformation,omitempty"`
}
type Artifact struct {
	ID          string   `json:"id"`
	State       string   `json:"state"`
	Input       *Bytes   `json:"input,omitempty"`
	Output      *Bytes   `json:"output,omitempty"`
	Changes     *Changes `json:"changes,omitempty"`
	Checks      *Checks  `json:"checks,omitempty"`
	ErrorCode   string   `json:"errorCode,omitempty"`
	PreExisting bool     `json:"preExisting,omitempty"`
}
type Changes struct {
	Metadata    []Change     `json:"metadata,omitempty"`
	SpecVersion *SpecChange  `json:"specVersion,omitempty"`
	Bulk        []BulkChange `json:"bulk,omitempty"`
}
type Change struct {
	Field     string `json:"field"`
	Operation string `json:"operation"`
	Before    any    `json:"before"`
	After     any    `json:"after"`
	Assertion string `json:"assertion"`
	Source    string `json:"source"`
}
type ValueSummary struct {
	Representation string `json:"representation"`
	SHA256         string `json:"sha256"`
	Bytes          int    `json:"bytes"`
}
type SpecChange struct {
	From string `json:"from"`
	To   string `json:"to"`
}
type BulkChange struct {
	Operation string         `json:"operation"`
	Scope     string         `json:"scope"`
	Evaluated int            `json:"evaluated"`
	Applied   int            `json:"applied"`
	Unmapped  int            `json:"unmapped"`
	Skipped   int            `json:"skipped"`
	Reasons   map[string]int `json:"reasons,omitempty"`
}
type Checks struct {
	Mode                  string   `json:"mode"`
	Gate                  string   `json:"gate"`
	Schema                string   `json:"schema"`
	SubjectRequirements   []string `json:"subjectRequirements,omitempty"`
	ComponentRequirements []string `json:"componentRequirements,omitempty"`
	ComponentScope        string   `json:"componentScope"`
	ComponentEvaluation   string   `json:"componentEvaluation"`
	ComponentsEvaluated   int      `json:"componentsEvaluated"`
	Findings              int      `json:"findings"`
	GraphFindings         int      `json:"graphFindings,omitempty"`
}
type Target struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}
type Exclusion struct {
	Rule       string `json:"rule,omitempty"`
	Scope      string `json:"scope,omitempty"`
	ArtifactID string `json:"artifactId,omitempty"`
	Target     string `json:"target,omitempty"`
	Reason     string `json:"reason"`
}
type Delivery struct {
	ProjectSource          string            `json:"projectSource,omitempty"`
	ArtifactID             string            `json:"artifactId"`
	Target                 string            `json:"target"`
	Project                map[string]string `json:"project,omitempty"`
	AttemptID              string            `json:"attemptId,omitempty"`
	Prior                  *Prior            `json:"prior,omitempty"`
	State                  string            `json:"state"`
	Intended               []Bytes           `json:"intended,omitempty"`
	Submitted              []Bytes           `json:"submitted,omitempty"`
	AttemptedAt            string            `json:"attemptedAt,omitempty"`
	RequestMayHaveOccurred bool              `json:"requestMayHaveOccurred"`
	Transport              Transport         `json:"transport"`
	Responses              []Response        `json:"responses,omitempty"`
	ErrorCode              string            `json:"errorCode,omitempty"`
}
type Transport struct {
	Scheme                  string `json:"scheme"`
	TLSObserved             *bool  `json:"tlsObserved,omitempty"`
	CertificateVerification string `json:"certificateVerification"`
}
type Response struct {
	AttemptedAt string      `json:"attemptedAt,omitempty"`
	Kind        string      `json:"kind"`
	Value       string      `json:"value"`
	HTTPStatus  int         `json:"httpStatus,omitempty"`
	ObservedAt  string      `json:"observedAt,omitempty"`
	Code        string      `json:"code,omitempty"`
	References  []Reference `json:"references,omitempty"`
}
type Reference struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}
