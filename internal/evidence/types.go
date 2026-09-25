// Package evidence consolidates recorded facts offline, without opening payloads
// or constructing adapters. Embedded source bytes remain the authority.
package evidence

import (
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/index"
)

const (
	MaxJournals       = 256
	MaxEvents         = 10000
	SourceLimit int64 = 32 << 20
	FileLimit   int64 = 128 << 20
)

type Validator func(record.Snapshot) error

// RetryValidator supplies adapter-owned policy compatibility without client construction.
type RetryValidator func(record.Intent, record.Intent) error

type Document struct {
	validator      Validator
	retryValidator RetryValidator
	SchemaVersion  int              `json:"schemaVersion"`
	Kind           string           `json:"kind"`
	Tool           index.Tool       `json:"tool"`
	Normalization  Normalization    `json:"normalization"`
	Deliveries     []Delivery       `json:"deliveries"`
	Coverage       Coverage         `json:"coverage"`
	Evidence       []SourceDocument `json:"evidence"`
}
type SourceDocument struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	MediaType string `json:"mediaType"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Encoding  string `json:"encoding"`
	Data      string `json:"data"`
}
type Normalization struct {
	EvidenceID            string          `json:"evidenceId"`
	IndexSHA256           string          `json:"indexSHA256"`
	Index                 json.RawMessage `json:"index"`
	SBOMBytesVerification string          `json:"sbomBytesVerification"`
}
type Delivery struct {
	AttemptID   string         `json:"attemptId"`
	ArtifactID  string         `json:"artifactId"`
	Intent      record.Intent  `json:"intent"`
	Events      []record.Event `json:"events"`
	Journal     Journal        `json:"journal"`
	EvidenceIDs []string       `json:"evidenceIds"`
	Summary     Summary        `json:"summary"`
}
type Journal struct {
	SHA256       string `json:"sha256"`
	EventCount   int    `json:"eventCount"`
	LastSequence int    `json:"lastSequence"`
}
type Summary struct {
	LatestVerification *Observation `json:"latestVerification,omitempty"`
	Acknowledgment     string       `json:"acknowledgment"`
	LatestActivity     *Observation `json:"latestActivity,omitempty"`
	LastObservation    *Observation `json:"lastObservation,omitempty"`
}
type Observation struct {
	Sequence    int                  `json:"sequence"`
	ObservedAt  string               `json:"observedAt"`
	Observation delivery.Observation `json:"observation"`
}
type Coverage struct {
	DeliverySelection                    string           `json:"deliverySelection"`
	SelectedDeliveryCount                int              `json:"selectedDeliveryCount"`
	ArtifactIDsWithoutSelectedDeliveries []string         `json:"artifactIdsWithoutSelectedDeliveries"`
	RetryAttemptIDsNotIncluded           []string         `json:"retryAttemptIdsNotIncluded"`
	SBOMFiles                            string           `json:"sbomFiles"`
	NormalizationInputs                  string           `json:"normalizationInputs"`
	NormalizationStatements              string           `json:"normalizationStatements"`
	Signatures                           string           `json:"signatures"`
	WorkerIdentity                       string           `json:"workerIdentity"`
	AuthenticatedProducerIdentity        string           `json:"authenticatedProducerIdentity"`
	CollectionNotes                      []CollectionNote `json:"collectionNotes"`
}
type CollectionNote struct {
	Code      string `json:"code"`
	AttemptID string `json:"attemptId"`
	Count     int    `json:"count"`
	Assertion string `json:"assertion"`
}
