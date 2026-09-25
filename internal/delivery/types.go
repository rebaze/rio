// Package delivery defines offline verified handoff and destination-neutral contracts.
package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"gopkg.in/yaml.v3"
	"io"
)

type Subject struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type Source struct {
	IndexSHA256     string `json:"indexSHA256"`
	ArtifactID      string `json:"artifactId"`
	OutputSHA256    string `json:"outputSHA256"`
	Gate            string `json:"gate"`
	SchemaValidated bool   `json:"schemaValidated"`
	AllowFailedGate bool   `json:"allowFailedGate"`
}
type PayloadRef struct {
	Role           string `json:"role"`
	MediaType      string `json:"mediaType"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
	SourceSHA256   string `json:"sourceSHA256"`
	Transformation string `json:"transformation"`
}
type Payload struct {
	ref  PayloadRef
	data []byte
}

func (p Payload) Ref() PayloadRef     { return p.ref }
func (p Payload) Open() io.ReadCloser { return io.NopCloser(bytes.NewReader(p.data)) }

type Verified struct {
	source   Source
	subject  Subject
	payloads []Payload
}

func (v Verified) Source() Source      { return v.source }
func (v Verified) Subject() Subject    { return v.subject }
func (v Verified) Payloads() []Payload { return append([]Payload(nil), v.payloads...) }

type Reference struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}
type Description struct {
	Type            string          `json:"type"`
	DestinationName string          `json:"destinationName"`
	Identity        json.RawMessage `json:"identity"`
	Options         json.RawMessage `json:"options"`
	CredentialRefs  []string        `json:"credentialRefs"`
	Capabilities    []string        `json:"capabilities"`
}
type Observation struct {
	Kind       string          `json:"kind"`
	Value      string          `json:"value"`
	Origin     string          `json:"origin"`
	Code       string          `json:"code"`
	HTTPStatus int             `json:"httpStatus,omitempty"`
	References []Reference     `json:"references"`
	Details    json.RawMessage `json:"details,omitempty"`
}
type Submission struct {
	Disposition  string        `json:"disposition"`
	References   []Reference   `json:"references"`
	Observations []Observation `json:"observations"`
}
type Preparation struct {
	Description        Description `json:"description"`
	ExpectedReferences []Reference `json:"expectedReferences,omitempty"`
}
type Planner interface {
	Prepare(Description, Source, []PayloadRef) (Preparation, error)
}

// Prepare supplies only copied metadata to an optional offline adapter planner.
func Prepare(p Provider, d Description, s Source, refs []PayloadRef) (Preparation, error) {
	d.Identity = append(json.RawMessage(nil), d.Identity...)
	d.Options = append(json.RawMessage(nil), d.Options...)
	d.CredentialRefs = append([]string{}, d.CredentialRefs...)
	d.Capabilities = append([]string{}, d.Capabilities...)
	if planner, ok := p.(Planner); ok {
		return planner.Prepare(d, s, append([]PayloadRef(nil), refs...))
	}
	return Preparation{Description: d}, nil
}
func HasCapability(d Description, capability string) bool {
	for _, c := range d.Capabilities {
		if c == capability {
			return true
		}
	}
	return false
}

type Provider interface {
	Describe(destination, binding yaml.Node, subject Subject) (Description, error)
	Build(Description, func(string) (string, bool)) (Target, error)
}
type Target interface {
	Submit(context.Context, []Payload) (Submission, error)
}
type Observer interface {
	Observe(context.Context, []Reference) (Observation, error)
}

// Error never includes raw configuration, credentials, or receiver error text.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string      { return e.Code + ": " + e.Message }
func Fail(code, field string) error { return &Error{code, field} }
