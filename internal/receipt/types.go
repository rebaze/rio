// Package receipt defines the unsigned, source-free snapshot of one Rio invocation.
// Paths and URLs are references only: parsing never opens or follows them.
package receipt

import "github.com/rebaze/rio/internal/gate"

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
	ID            string         `json:"id"`
	State         string         `json:"state"`
	Input         *Bytes         `json:"input,omitempty"`
	Output        *Bytes         `json:"output,omitempty"`
	Changes       *Changes       `json:"changes,omitempty"`
	Checks        *Checks        `json:"checks,omitempty"`
	Distributions []Distribution `json:"distributions,omitempty"`
	ErrorCode     string         `json:"errorCode,omitempty"`
	PreExisting   bool           `json:"preExisting,omitempty"`
}

// Distribution is a producer-asserted digest of a shipped file; Rio never hashes
// the file, so the assertion is always "producer".
type Distribution struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	Assertion string `json:"assertion"`
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
	// Failed names each failed requirement and how often it failed, in the
	// fixed order of FailedRequirementIDs. Present only when the gate failed;
	// receipts written before it existed omit it even then.
	Failed []FailedRequirement `json:"failed,omitempty"`
	// Profile names the gate profile the artifact was checked against, and
	// ProfileLevels counts the components found at each level. Both are
	// absent when no profile ran.
	Profile       *ProfileRef    `json:"profile,omitempty"`
	ProfileLevels map[string]int `json:"profileLevels,omitempty"`
}

// ProfileRef identifies a gate profile and the guideline version it encodes.
type ProfileRef struct {
	Name             string `json:"name"`
	Guideline        string `json:"guideline"`
	GuidelineVersion string `json:"guidelineVersion"`
}

// ProfileLevelKeys are the keys profileLevels holds, in level order.
var ProfileLevelKeys = gate.LevelOrder

// knownProfile reports whether p names a profile rio ships, with that
// profile's guideline and version.
func knownProfile(p *ProfileRef) bool {
	if p == nil {
		return false
	}
	known, ok := gate.LookupProfile(p.Name)
	return ok && known.Guideline == p.Guideline && known.GuidelineVersion == p.GuidelineVersion
}

// FailedRequirement is one requirement that failed and how many times: once
// for a subject requirement, once per affected component otherwise.
type FailedRequirement struct {
	Requirement string `json:"requirement"`
	Count       int    `json:"count"`
}

// FailedRequirementIDs are the stable requirement identifiers, in reporting
// order: the scope, a dot, and the field the requirement concerns.
func FailedRequirementIDs() []string {
	return []string{
		"sbom.specVersion", "sbom.creator", "sbom.timestamp", "sbom.vulnerabilities",
		"subject.name", "subject.version", "subject.level", "subject.creator", "subject.filename", "subject.dependencies",
		"subject.distributionLicences", "subject.deployableHash", "subject.executable", "subject.archive", "subject.structured",
		"subject.securityContact", "subject.digest",
		"components.name", "components.version", "components.purl", "components.level", "components.creator", "components.filename",
		"components.dependencies", "components.distributionLicences", "components.deployableHash", "components.executable",
		"components.archive", "components.structured",
	}
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
	// ProjectFields are the Dependency-Track tags, parent and isLatest the
	// delivery requested and what a read-back observed. Absent when none of
	// them is configured; receipts written before they existed omit them.
	ProjectFields *ProjectFields `json:"projectFields,omitempty"`
}

// ProjectFields record each requested value with a state: "observed" when a
// read-back showed it, "different" when it showed another value (kept as
// observed), and "unknown" when the project was not read. ReadBack is "read",
// "not-attempted" before an accepted upload, or why the read failed.
type ProjectFields struct {
	ReadBack string              `json:"readBack"`
	Tags     *ProjectTagsField   `json:"tags,omitempty"`
	Parent   *ProjectParentField `json:"parent,omitempty"`
	IsLatest *ProjectLatestField `json:"isLatest,omitempty"`
}
type ProjectTagsField struct {
	Requested []string  `json:"requested"`
	State     string    `json:"state"`
	Observed  *[]string `json:"observed,omitempty"`
}
type ProjectParent struct {
	UUID    string `json:"uuid,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}
type ProjectParentField struct {
	Requested ProjectParent  `json:"requested"`
	State     string         `json:"state"`
	Observed  *ProjectParent `json:"observed,omitempty"`
}
type ProjectLatestField struct {
	Requested bool   `json:"requested"`
	State     string `json:"state"`
	Observed  *bool  `json:"observed,omitempty"`
}
type Transport struct {
	Scheme                  string `json:"scheme"`
	TLSObserved             *bool  `json:"tlsObserved,omitempty"`
	CertificateVerification string `json:"certificateVerification"`
}
type Response struct {
	TLSObserved *bool       `json:"tlsObserved,omitempty"`
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
