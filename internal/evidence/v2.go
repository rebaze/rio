package evidence

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"sort"
	"strings"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/batchrecord"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/index"
)

const MaxJournalsV2 = 1024

// documentV2 is a separate wire contract. V1 never serializes these new fields.
type documentV2 struct {
	SchemaVersion int              `json:"schemaVersion"`
	Kind          string           `json:"kind"`
	Tool          index.Tool       `json:"tool"`
	Normalization Normalization    `json:"normalization"`
	Deliveries    []Delivery       `json:"deliveries"`
	Coverage      Coverage         `json:"coverage"`
	ExpectedScope string           `json:"expectedScope"`
	Batches       []BatchView      `json:"batches"`
	Evidence      []SourceDocument `json:"evidence"`
}
type BatchView struct {
	SHA256               string                  `json:"sha256"`
	DescriptorEvidenceID string                  `json:"descriptorEvidenceId"`
	CompletionEvidenceID string                  `json:"completionEvidenceId,omitempty"`
	Scope                batchrecord.Descriptor  `json:"scope"`
	Completion           *batchrecord.Completion `json:"completion,omitempty"`
	Pairs                []PairCoverage          `json:"pairs"`
	Exclusions           []Exclusion             `json:"exclusions"`
}
type PairCoverage struct {
	PairID         string `json:"pairId"`
	ArtifactID     string `json:"artifactId"`
	Target         string `json:"target"`
	AttemptID      string `json:"attemptId"`
	Evidence       string `json:"evidence"`
	Acknowledgment string `json:"acknowledgment"`
	RunnerState    string `json:"runnerState"`
}

// Exclusion describes an exact Cartesian subset without expanding a potentially
// huge filtered routing matrix. Reasons are disjoint, so counts do not overlap.
type Exclusion struct {
	Reason      string   `json:"reason"`
	ArtifactIDs []string `json:"artifactIDs"`
	Targets     []string `json:"targets"`
	PairCount   int64    `json:"pairCount"`
}
type capturedBatch struct{ descriptor, completion []byte }
type documentV1 Document

func wireDocument(d Document) any {
	if d.SchemaVersion == 2 {
		return documentV2{d.SchemaVersion, d.Kind, d.Tool, d.Normalization, d.Deliveries, d.Coverage, d.ExpectedScope, d.Batches, d.Evidence}
	}
	return documentV1(d)
}
func (d Document) MarshalJSON() ([]byte, error) {
	var out bytes.Buffer
	e := json.NewEncoder(&out)
	e.SetEscapeHTML(false)
	if err := e.Encode(wireDocument(d)); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}
func fromV2(v documentV2) Document {
	return Document{SchemaVersion: v.SchemaVersion, Kind: v.Kind, Tool: v.Tool, Normalization: v.Normalization, Deliveries: v.Deliveries, Coverage: v.Coverage, ExpectedScope: v.ExpectedScope, Batches: v.Batches, Evidence: v.Evidence}
}

func assembleV2(indexRaw []byte, captures []record.Capture, batches []capturedBatch, version string, validate Validator, retryPolicy ...RetryValidator) (Document, error) {
	if len(batches) > batchrecord.MaxBatches || len(captures) > MaxJournalsV2 {
		return Document{}, limitError()
	}
	total := int64(len(indexRaw))
	for _, c := range captures {
		for _, b := range c.RawEvents {
			total += int64(len(b))
		}
	}
	for _, b := range batches {
		total += int64(len(b.descriptor) + len(b.completion))
		if total > SourceLimit {
			return Document{}, limitError()
		}
	}
	d, err := assembleLimited(indexRaw, captures, version, MaxJournalsV2, validate, retryPolicy...)
	if err != nil {
		return d, err
	}
	d.SchemaVersion = 2
	d.ExpectedScope = "not-recorded"
	d.Batches = []BatchView{}
	if len(batches) > 0 {
		d.ExpectedScope = "recorded"
		d.Coverage.DeliverySelection = "explicit-batches-and-journals"
	}
	sort.Slice(batches, func(i, j int) bool {
		return delivery.Digest(batches[i].descriptor) < delivery.Digest(batches[j].descriptor)
	})
	journals := map[string]record.Snapshot{}
	for _, c := range captures {
		journals[c.Snapshot.Events[0].AttemptID] = c.Snapshot
	}
	seen := map[string]bool{}
	bound := map[string]bool{}
	pairPolicies := map[string]record.Intent{}
	// Every repeated receiver/source pairing must preserve the current retry
	// compatibility policy, including explicitly added journals outside batches.
	for _, capture := range captures {
		i := capture.Snapshot.Intent
		key := delivery.PairKey(i.Source, i.Destination)
		if prior, ok := pairPolicies[key]; ok && !compatible(i, prior, retryPolicy...) {
			return Document{}, delivery.Fail("retry_mismatch", "repeated pair policies differ")
		}
		pairPolicies[key] = i
	}
	for _, b := range batches {
		desc, err := batchrecord.ParseDescriptor(b.descriptor)
		if err != nil {
			return Document{}, err
		}
		sha := delivery.Digest(b.descriptor)
		if seen[sha] {
			return Document{}, delivery.Fail("duplicate_batch", "batch selected more than once")
		}
		seen[sha] = true
		if err = batchrecord.ValidateIndex(desc, indexRaw); err != nil {
			return Document{}, err
		}
		view := BatchView{SHA256: sha, DescriptorEvidenceID: "batch/" + sha, Scope: desc, Pairs: []PairCoverage{}, Exclusions: exclusions(desc)}
		d.Evidence = append(d.Evidence, source(view.DescriptorEvidenceID, "delivery-batch", b.descriptor))
		if len(b.completion) > 0 {
			c, err := batchrecord.ParseCompletion(b.completion, desc, b.descriptor)
			if err != nil {
				return Document{}, err
			}
			view.Completion = &c
			view.CompletionEvidenceID = "batch-result/" + sha
			d.Evidence = append(d.Evidence, source(view.CompletionEvidenceID, "delivery-batch-result", b.completion))
		}
		for i, p := range desc.Pairs {
			if bound[p.AttemptID] {
				return Document{}, delivery.Fail("duplicate_attempt", "attempt bound by multiple batches")
			}
			bound[p.AttemptID] = true
			if prior, ok := pairPolicies[p.ID]; ok && !compatible(p.Intent, prior, retryPolicy...) {
				return Document{}, delivery.Fail("retry_mismatch", "batch pair policies differ")
			}
			pairPolicies[p.ID] = p.Intent
			// Validate adapter-owned preparation even when its journal is missing. This
			// empty snapshot is used only as an offline policy check, never as evidence.
			if validate != nil {
				if err = validate(record.Snapshot{Intent: p.Intent}); err != nil {
					return Document{}, err
				}
			}
			coverage := PairCoverage{PairID: p.ID, ArtifactID: p.ArtifactID, Target: p.Target, AttemptID: p.AttemptID, Evidence: "missing", Acknowledgment: "not-captured", RunnerState: "not-recorded"}
			if view.Completion != nil {
				coverage.RunnerState = view.Completion.Items[i].State
			}
			if s, ok := journals[p.AttemptID]; ok {
				if err = batchrecord.CheckPairJournal(p, s); err != nil {
					return Document{}, err
				}
				if view.Completion != nil {
					if err = batchrecord.CheckCompletionJournal(view.Completion.Items[i], s); err != nil {
						return Document{}, err
					}
				}
				coverage.Evidence = "captured"
				coverage.Acknowledgment = s.Disposition
			}
			view.Pairs = append(view.Pairs, coverage)
		}
		d.Batches = append(d.Batches, view)
	}
	return d, nil
}

func validateDocumentV2(d Document, validate Validator, retryPolicy ...RetryValidator) (Document, error) {
	if d.SchemaVersion != 2 || d.Kind != "rio-evidence-record" || d.Tool.Name != "rio" || d.Tool.Version == "" || d.Batches == nil || d.Deliveries == nil || d.Evidence == nil {
		return Document{}, invalid()
	}
	if len(d.Batches) > batchrecord.MaxBatches || len(d.Deliveries) > MaxJournalsV2 || len(d.Evidence) > MaxEvents+1+2*batchrecord.MaxBatches {
		return Document{}, limitError()
	}
	var total int64
	ids := map[string]bool{}
	for _, s := range d.Evidence {
		if ids[s.ID] || s.MediaType != "application/json" || s.Encoding != "base64" || !delivery.ValidDigest(s.SHA256) || s.Size < 0 {
			return Document{}, invalid()
		}
		ids[s.ID] = true
		var bound int64
		switch s.Kind {
		case "normalization-index":
			bound = delivery.IndexLimit
			if s.ID != "normalization-index" {
				return Document{}, invalid()
			}
		case "delivery-event":
			bound = record.EventLimit
		case "delivery-batch", "delivery-batch-result":
			bound = batchrecord.SourceLimit
		default:
			return Document{}, delivery.Fail("unsupported_evidence_kind", "source kind")
		}
		if s.Size > bound || s.Size > SourceLimit-total {
			return Document{}, limitError()
		}
		total += s.Size
		if int64(len(s.Data)) != int64(base64.StdEncoding.EncodedLen(int(s.Size))) {
			return Document{}, invalid()
		}
	}
	var indexRaw []byte
	groups := map[string][][]byte{}
	descriptors := map[string][]byte{}
	completions := map[string][]byte{}
	for _, s := range d.Evidence {
		b, e := base64.StdEncoding.Strict().DecodeString(s.Data)
		if e != nil || int64(len(b)) != s.Size || delivery.Digest(b) != s.SHA256 || base64.StdEncoding.EncodeToString(b) != s.Data {
			return Document{}, invalid()
		}
		switch s.Kind {
		case "normalization-index":
			indexRaw = b
		case "delivery-batch":
			if s.ID != "batch/"+s.SHA256 {
				return Document{}, invalid()
			}
			descriptors[s.SHA256] = b
		case "delivery-batch-result":
			key := strings.TrimPrefix(s.ID, "batch-result/")
			if key == s.ID || !delivery.ValidDigest(key) {
				return Document{}, invalid()
			}
			completions[key] = b
		case "delivery-event":
			parts := strings.Split(s.ID, "/")
			if len(parts) != 3 || parts[0] != "delivery" || len(parts[1]) != 32 || len(parts[2]) != 20 || s.ID != eventID(parts[1], len(groups[parts[1]])) {
				return Document{}, invalid()
			}
			groups[parts[1]] = append(groups[parts[1]], b)
		}
	}
	if indexRaw == nil || len(groups) > MaxJournalsV2 || len(descriptors) > batchrecord.MaxBatches {
		return Document{}, invalid()
	}
	captures := []record.Capture{}
	for id, raw := range groups {
		s, e := record.DecodeEvents(raw)
		if e != nil {
			return Document{}, e
		}
		if s.Events[0].AttemptID != id {
			return Document{}, invalid()
		}
		captures = append(captures, record.Capture{Snapshot: s, RawEvents: raw})
	}
	batches := []capturedBatch{}
	for key, raw := range descriptors {
		batches = append(batches, capturedBatch{raw, completions[key]})
		delete(completions, key)
	}
	if len(completions) > 0 {
		return Document{}, invalid()
	}
	expected, e := assembleV2(indexRaw, captures, batches, d.Tool.Version, validate, retryPolicy...)
	if e != nil {
		return Document{}, e
	}
	if e = copyCollectionNotes(d, &expected); e != nil {
		return Document{}, e
	}
	if encodedSize(reflect.ValueOf(wireDocument(d)))+1 > FileLimit {
		return Document{}, limitError()
	}
	a, e := encodeDocument(d)
	if e != nil {
		return Document{}, e
	}
	b, e := encodeDocument(expected)
	if e != nil {
		return Document{}, e
	}
	if !jsonEqual(a, b) {
		return Document{}, delivery.Fail("evidence_mismatch", "readable facts differ from embedded sources")
	}
	return expected, nil
}

func copyCollectionNotes(d Document, expected *Document) error {
	if d.Coverage.CollectionNotes == nil {
		return invalid()
	}
	positions := map[string]int{}
	counts := map[string]int{}
	for i, x := range expected.Deliveries {
		positions[x.AttemptID] = i
		counts[x.AttemptID] = len(x.Events)
	}
	previous := -1
	for _, n := range d.Coverage.CollectionNotes {
		pos, ok := positions[n.AttemptID]
		if !ok || pos <= previous || n.Code != "orphan-temporary-files" || n.Assertion != "collector" || n.Count <= 0 || n.Count > record.MaxDirectoryEntries-counts[n.AttemptID] {
			return invalid()
		}
		previous = pos
	}
	expected.Coverage.CollectionNotes = append([]CollectionNote{}, d.Coverage.CollectionNotes...)
	return nil
}
