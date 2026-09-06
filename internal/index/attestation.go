package index

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// A statement binds one normalized SBOM's digest to its complete run record.
// It is unsigned: signing and verification belong to the tools outside rio.
type statement struct {
	Type          string                 `json:"_type"`
	Subject       []statementSubject     `json:"subject"`
	PredicateType string                 `json:"predicateType"`
	Predicate     normalizationPredicate `json:"predicate"`
}

type statementSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Keep the artifact intact rather than projecting selected fields: its
// identity, findings, and any future index fields must survive in the claim.
type normalizationPredicate struct {
	Tool     Tool     `json:"tool"`
	Manifest FileRef  `json:"manifest"`
	Artifact Artifact `json:"artifact"`
}

// MarshalStatements returns one unsigned in-toto Statement v1 per artifact,
// in index order. The caller supplies the same index whose output digests
// were computed from disk, and writes each result beside its subject SBOM.
//
// The predicate uses the index's normalization so its artifact round-trips
// the serialized index row exactly, including empty arrays and optional
// findings. As with Marshal, the caller's index is not mutated and no
// timestamps or machine-local paths are introduced.
func MarshalStatements(idx *Index) ([][]byte, error) {
	if err := idx.Validate(); err != nil {
		return nil, err
	}
	normalized := normalize(idx)
	statements := make([][]byte, 0, len(normalized.Artifacts))
	for _, a := range normalized.Artifacts {
		s := statement{
			Type: "https://in-toto.io/Statement/v1",
			Subject: []statementSubject{{
				Name:   a.Output.Path,
				Digest: map[string]string{"sha256": a.Output.SHA256},
			}},
			PredicateType: "https://rebaze.com/attestation/sbom-normalization/v1",
			Predicate: normalizationPredicate{
				Tool: normalized.Tool, Manifest: normalized.Manifest, Artifact: a,
			},
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(s); err != nil {
			return nil, fmt.Errorf("artifact %q: serializing attestation: %w", a.ID, err)
		}
		statements = append(statements, buf.Bytes())
	}
	return statements, nil
}
