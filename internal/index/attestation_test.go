package index_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/rebaze/rio/internal/index"
)

func TestMarshalStatementsPreservesEveryArtifactField(t *testing.T) {
	idx := fullIndex()
	statements, err := index.MarshalStatements(idx)
	if err != nil {
		t.Fatal(err)
	}
	if len(statements) != 2 {
		t.Fatalf("got %d statements, want 2", len(statements))
	}
	for i, data := range statements {
		var got struct {
			Type    string `json:"_type"`
			Subject []struct {
				Name   string            `json:"name"`
				Digest map[string]string `json:"digest"`
			} `json:"subject"`
			PredicateType string `json:"predicateType"`
			Predicate     struct {
				Tool     index.Tool     `json:"tool"`
				Manifest index.FileRef  `json:"manifest"`
				Artifact index.Artifact `json:"artifact"`
			} `json:"predicate"`
		}
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("statement %d: %v", i, err)
		}
		if got.Type != "https://in-toto.io/Statement/v1" || got.PredicateType != "https://rebaze.com/attestation/sbom-normalization/v1" {
			t.Errorf("statement %d has unexpected types: %q, %q", i, got.Type, got.PredicateType)
		}
		if len(got.Subject) != 1 {
			t.Fatalf("statement %d has %d subjects, want 1", i, len(got.Subject))
		}
		want := idx.Artifacts[i]
		if got.Subject[0].Name != want.Output.Path || got.Subject[0].Digest["sha256"] != want.Output.SHA256 {
			t.Errorf("statement %d subject does not identify its artifact output: %+v", i, got.Subject[0])
		}
		if diff := cmp.Diff(want, got.Predicate.Artifact); diff != "" {
			t.Errorf("statement %d lost artifact fields (-want +got):\n%s", i, diff)
		}
		if diff := cmp.Diff(idx.Tool, got.Predicate.Tool); diff != "" {
			t.Errorf("statement %d lost tool identity (-want +got):\n%s", i, diff)
		}
		if diff := cmp.Diff(idx.Manifest, got.Predicate.Manifest); diff != "" {
			t.Errorf("statement %d lost manifest identity (-want +got):\n%s", i, diff)
		}
	}
}

func TestMarshalStatementsNormalizesCopy(t *testing.T) {
	idx := fullIndex()
	idx.SchemaVersion = 0
	idx.Tool.Name = ""
	idx.Artifacts[0].Transforms = nil
	idx.Artifacts[0].GateFindings = nil
	idx.Artifacts[1].GateFindings[0].Missing = nil
	before, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	statements, err := index.MarshalStatements(idx)
	if err != nil {
		t.Fatal(err)
	}
	if len(statements) != 2 {
		t.Fatalf("got %d statements, want 2", len(statements))
	}
	for i, data := range statements {
		var got struct {
			Predicate struct {
				Tool     index.Tool                 `json:"tool"`
				Artifact map[string]json.RawMessage `json:"artifact"`
			} `json:"predicate"`
		}
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if got.Predicate.Tool.Name != "rio" {
			t.Errorf("statement %d tool name = %q, want rio", i, got.Predicate.Tool.Name)
		}
		if bytes.Contains(data, []byte("null")) {
			t.Errorf("statement %d contains null: %s", i, data)
		}
		if i == 0 {
			for _, field := range []string{"transforms", "gateFindings"} {
				if string(got.Predicate.Artifact[field]) != "[]" {
					t.Errorf("%s = %s, want []", field, got.Predicate.Artifact[field])
				}
			}
			if _, exists := got.Predicate.Artifact["integrityFindings"]; exists {
				t.Error("empty integrityFindings must remain omitted")
			}
		} else {
			var findings []struct {
				Missing []string `json:"missing"`
			}
			if err := json.Unmarshal(got.Predicate.Artifact["gateFindings"], &findings); err != nil {
				t.Fatal(err)
			}
			if len(findings) != 2 || findings[0].Missing == nil || len(findings[0].Missing) != 0 {
				t.Errorf("gate findings lost their normalized missing array: %+v", findings)
			}
		}
	}
	after, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("MarshalStatements mutated the caller:\nbefore: %s\nafter: %s", before, after)
	}
}

func TestMarshalStatementsRejectsInvalidIndexWithoutPartialOutput(t *testing.T) {
	tests := []struct {
		name string
		edit func(*index.Index) *index.Index
	}{
		{"nil", func(*index.Index) *index.Index { return nil }},
		{"missing id", func(idx *index.Index) *index.Index { idx.Artifacts[1].ID = ""; return idx }},
		{"duplicate id", func(idx *index.Index) *index.Index { idx.Artifacts[1].ID = idx.Artifacts[0].ID; return idx }},
		{"unset gate", func(idx *index.Index) *index.Index { idx.Artifacts[1].Gate = ""; return idx }},
		{"unknown gate", func(idx *index.Index) *index.Index { idx.Artifacts[1].Gate = "warn"; return idx }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := index.MarshalStatements(tt.edit(fullIndex()))
			if err == nil {
				t.Fatal("invalid index accepted")
			}
			if tt.name == "nil" && !errors.Is(err, index.ErrNilIndex) {
				t.Errorf("nil index error = %v, want ErrNilIndex", err)
			}
			if got != nil {
				t.Errorf("invalid index returned partial statements: %q", got)
			}
		})
	}
}
