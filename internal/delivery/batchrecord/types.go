// Package batchrecord owns immutable delivery scope and runner assertions.
// These are recovery sources, never substitutes for committed acknowledgments.
package batchrecord

import (
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
)

const SourceLimit int64 = 16 << 20
const MaxPairs = 1024
const MaxBatches = 256

type File struct {
	PathHint string `json:"pathHint"`
	SHA256   string `json:"sha256"`
}
type Descriptor struct {
	SchemaVersion               int                 `json:"schemaVersion"`
	Kind                        string              `json:"kind"`
	Index                       File                `json:"index"`
	NormalizationManifestSHA256 string              `json:"normalizationManifestSHA256"`
	DeliveryManifestSHA256      string              `json:"deliveryManifestSHA256"`
	CompletionPathHint          string              `json:"completionPathHint"`
	ArtifactIDs                 []string            `json:"artifactIDs"`
	Scope                       delivery.BatchScope `json:"scope"`
	Pairs                       []Pair              `json:"pairs"`
}
type Pair struct {
	AttemptID       string        `json:"attemptId"`
	ID              string        `json:"id"`
	ArtifactID      string        `json:"artifactId"`
	Target          string        `json:"target"`
	JournalPathHint string        `json:"journalPathHint"`
	Intent          record.Intent `json:"intent"`
}
type Completion struct {
	SchemaVersion          int              `json:"schemaVersion"`
	Kind                   string           `json:"kind"`
	BatchSHA256            string           `json:"batchSHA256"`
	Outcome                string           `json:"outcome"`
	RequestMayHaveOccurred bool             `json:"requestMayHaveOccurred"`
	ErrorCode              string           `json:"errorCode,omitempty"`
	Items                  []CompletionItem `json:"items"`
}
type CompletionItem struct {
	PairID                 string `json:"pairId"`
	State                  string `json:"state"`
	AttemptID              string `json:"attemptId,omitempty"`
	Acknowledgment         string `json:"acknowledgment,omitempty"`
	RequestMayHaveOccurred bool   `json:"requestMayHaveOccurred"`
	ErrorCode              string `json:"errorCode,omitempty"`
}

// New binds the already prepared intents, never builds clients or reads a file.
func New(plan delivery.BatchPlan, intents []record.Intent, attemptIDs []string, paths Paths) (Descriptor, error) {
	raw := plan.IndexBytes()
	idx, err := delivery.ParseIndex(raw)
	if err != nil {
		return Descriptor{}, err
	}
	d := Descriptor{SchemaVersion: 1, Kind: "rio-delivery-batch", Index: File{paths.Index, plan.IndexSHA256}, NormalizationManifestSHA256: idx.Manifest.SHA256, DeliveryManifestSHA256: plan.ManifestSHA256, CompletionPathHint: paths.Completion, ArtifactIDs: []string{}, Scope: plan.Scope, Pairs: []Pair{}}
	if len(intents) != len(plan.Jobs) || len(attemptIDs) != len(plan.Jobs) {
		return Descriptor{}, invalid()
	}
	for _, a := range idx.Artifacts {
		d.ArtifactIDs = append(d.ArtifactIDs, a.ID)
	}
	for i, j := range plan.Jobs {
		d.Pairs = append(d.Pairs, Pair{AttemptID: attemptIDs[i], ID: delivery.PairKey(j.Verified.Source(), j.Description), ArtifactID: j.ArtifactID, Target: j.Target, JournalPathHint: j.Record, Intent: intents[i]})
	}
	if err = ValidateIndex(d, raw); err != nil {
		return Descriptor{}, err
	}
	// Own every nested byte/slice instead of exposing plan/caller state.
	encoded, err := MarshalDescriptor(d)
	if err != nil {
		return Descriptor{}, err
	}
	return ParseDescriptor(encoded)
}

func MarshalDescriptor(d Descriptor) ([]byte, error) {
	if err := Validate(d); err != nil {
		return nil, err
	}
	// Bound before the final encoder can buffer the entire descriptor.
	base := d
	base.Pairs = nil
	b, err := json.Marshal(base)
	if err != nil {
		return nil, invalid()
	}
	size := int64(len(b))
	for _, p := range d.Pairs {
		b, err = json.Marshal(p)
		if err != nil {
			return nil, invalid()
		}
		size += int64(len(b)) + 1
		if size > SourceLimit {
			return nil, limit()
		}
	}
	b, err = json.Marshal(d)
	if err != nil {
		return nil, invalid()
	}
	b = append(b, '\n')
	if int64(len(b)) > SourceLimit {
		return nil, limit()
	}
	return b, nil
}
func MarshalCompletion(c Completion, d Descriptor, batchRaw []byte) ([]byte, error) {
	if err := ValidateCompletion(c, d, batchRaw); err != nil {
		return nil, err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil, invalid()
	}
	b = append(b, '\n')
	if int64(len(b)) > SourceLimit {
		return nil, limit()
	}
	return b, nil
}
