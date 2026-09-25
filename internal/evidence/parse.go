package evidence

import (
	"encoding/base64"
	"strings"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
)

// Parse checks source bytes, shared journal invariants, cross-record links and
// every readable projection. It never follows an embedded path or URL.
func Parse(raw []byte, validate Validator, retryPolicy ...RetryValidator) (Document, error) {
	if int64(len(raw)) > FileLimit {
		return Document{}, limitError()
	}
	if e := preflightRecord(raw); e != nil {
		return Document{}, e
	}
	var d Document
	if e := delivery.DecodeJSON(raw, &d, true); e != nil {
		return Document{}, e
	}
	return validateDocument(d, validate, retryPolicy...)
}
func validateDocument(d Document, validate Validator, retryPolicy ...RetryValidator) (Document, error) {
	if d.SchemaVersion != 1 || d.Kind != "rio-evidence-record" || d.Tool.Name != "rio" || d.Tool.Version == "" {
		return Document{}, invalid()
	}
	if len(d.Deliveries) > MaxJournals || len(d.Evidence) > MaxEvents+1 {
		return Document{}, limitError()
	}
	if d.Deliveries == nil || d.Evidence == nil || d.Coverage.CollectionNotes == nil || d.Coverage.ArtifactIDsWithoutSelectedDeliveries == nil || d.Coverage.RetryAttemptIDsNotIncluded == nil {
		return Document{}, invalid()
	}
	// Check ALL declared and encoded bounds before decoding any source buffer.
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
		default:
			return Document{}, delivery.Fail("unsupported_evidence_kind", "source kind")
		}
		if s.Size > bound || s.Size > SourceLimit-total {
			return Document{}, limitError()
		}
		total += s.Size
		// A strict standard encoding has exactly this length, no CR/LF or aliases.
		if int64(len(s.Data)) != int64(base64.StdEncoding.EncodedLen(int(s.Size))) {
			return Document{}, invalid()
		}
	}
	var indexRaw []byte
	groups := map[string][][]byte{}
	for _, s := range d.Evidence {
		b, e := base64.StdEncoding.Strict().DecodeString(s.Data)
		if e != nil || int64(len(b)) != s.Size || delivery.Digest(b) != s.SHA256 || base64.StdEncoding.EncodeToString(b) != s.Data {
			return Document{}, invalid()
		}
		if s.Kind == "normalization-index" {
			indexRaw = b
			continue
		}
		parts := strings.Split(s.ID, "/")
		if len(parts) != 3 || parts[0] != "delivery" || len(parts[1]) != 32 || len(parts[2]) != 20 {
			return Document{}, invalid()
		}
		group := groups[parts[1]]
		if s.ID != eventID(parts[1], len(group)) {
			return Document{}, invalid()
		}
		groups[parts[1]] = append(group, b)
	}
	if indexRaw == nil || len(groups) > MaxJournals {
		return Document{}, invalid()
	}
	captures := make([]record.Capture, 0, len(groups))
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
	expected, e := assemble(indexRaw, captures, d.Tool.Version, validate, retryPolicy...)
	if e != nil {
		return Document{}, e
	}
	// Notes are checked collector assertions, never reconstructed historical proof.
	position := map[string]int{}
	counts := map[string]int{}
	for n, x := range expected.Deliveries {
		position[x.AttemptID] = n
		counts[x.AttemptID] = len(x.Events)
	}
	prev := -1
	for _, note := range d.Coverage.CollectionNotes {
		pos, ok := position[note.AttemptID]
		if !ok || pos <= prev || note.Code != "orphan-temporary-files" || note.Assertion != "collector" || note.Count <= 0 || note.Count > record.MaxDirectoryEntries-counts[note.AttemptID] {
			return Document{}, invalid()
		}
		prev = pos
	}
	expected.Coverage.CollectionNotes = append([]CollectionNote{}, d.Coverage.CollectionNotes...)
	// Compare opaque summary facts before re-encoding the whole readable document.
	// A forged projection must not make the JSON encoder repeatedly buffer a large
	// adapter-owned value. Raw evidence still supplies the independently rebuilt facts.
	if len(d.Deliveries) != len(expected.Deliveries) {
		return Document{}, invalid()
	}
	for i, x := range d.Deliveries {
		if x.AttemptID != expected.Deliveries[i].AttemptID || !summaryDetailsEqual(x.Summary, expected.Deliveries[i].Summary) {
			return Document{}, delivery.Fail("evidence_mismatch", "readable facts differ from embedded sources")
		}
	}
	// Canonical JSON values preserve integer tokens instead of passing through float64.
	claimed, e := encodeDocument(d)
	if e != nil {
		return Document{}, e
	}
	rebuilt, e := encodeDocument(expected)
	if e != nil {
		return Document{}, e
	}
	if !jsonEqual(claimed, rebuilt) {
		return Document{}, delivery.Fail("evidence_mismatch", "readable facts differ from embedded sources")
	}
	return expected, nil
}

func summaryDetailsEqual(a, b Summary) bool {
	for _, pair := range [][2]*Observation{{a.LatestVerification, b.LatestVerification}, {a.LatestActivity, b.LatestActivity}, {a.LastObservation, b.LastObservation}} {
		if (pair[0] == nil) != (pair[1] == nil) {
			return false
		}
		if pair[0] == nil {
			continue
		}
		ar, br := pair[0].Observation.Details, pair[1].Observation.Details
		if len(ar) == 0 && len(br) == 0 {
			continue
		}
		if !jsonEqual(ar, br) {
			return false
		}
	}
	return true
}
