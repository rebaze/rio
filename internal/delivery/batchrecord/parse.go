package batchrecord

import (
	"bytes"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
)

func invalid() error {
	return delivery.Fail("invalid_batch_evidence", "batch source structure or relationship")
}
func limit() error { return delivery.Fail("size_limit", "batch source limit") }

var attemptID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var errorCode = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,127}$`)

func preflight(raw []byte, model any, array string) error {
	if int64(len(raw)) > SourceLimit {
		return limit()
	}
	if err := delivery.PreflightJSON(raw, model); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil {
		return invalid()
	}
	for dec.More() {
		token, _ := dec.Token()
		if token == array {
			if token, err := dec.Token(); err != nil || token != json.Delim('[') {
				return invalid()
			}
			count := 0
			for dec.More() {
				if count >= MaxPairs {
					return limit()
				}
				var discard json.RawMessage
				if err := dec.Decode(&discard); err != nil {
					return invalid()
				}
				count++
			}
			if _, err := dec.Token(); err != nil {
				return invalid()
			}
		} else {
			var discard json.RawMessage
			if err := dec.Decode(&discard); err != nil {
				return invalid()
			}
		}
	}
	return nil
}
func ParseDescriptor(raw []byte) (Descriptor, error) {
	var d Descriptor
	if err := preflight(raw, &d, "pairs"); err != nil {
		return d, err
	}
	if err := delivery.DecodeJSON(raw, &d, true); err != nil {
		return d, err
	}
	return d, Validate(d)
}
func ParseCompletion(raw []byte, d Descriptor, batchRaw []byte) (Completion, error) {
	var c Completion
	if err := preflight(raw, &c, "items"); err != nil {
		return c, err
	}
	if err := delivery.DecodeJSON(raw, &c, true); err != nil {
		return c, err
	}
	return c, ValidateCompletion(c, d, batchRaw)
}
func inventory(values []string) (map[string]bool, error) {
	if values == nil {
		return nil, invalid()
	}
	out := map[string]bool{}
	for _, v := range values {
		if v == "" || out[v] {
			return nil, invalid()
		}
		out[v] = true
	}
	return out, nil
}
func selected(filter []string, all map[string]bool) (map[string]bool, error) {
	if filter == nil {
		return nil, invalid()
	}
	if len(filter) == 0 {
		return all, nil
	}
	out, err := inventory(filter)
	if err != nil {
		return nil, err
	}
	for v := range out {
		if !all[v] {
			return nil, invalid()
		}
	}
	return out, nil
}
func Validate(d Descriptor) error {
	if d.SchemaVersion != 1 || d.Kind != "rio-delivery-batch" || d.Index.PathHint == "" || d.CompletionPathHint == "" || !delivery.ValidDigest(d.Index.SHA256) || !delivery.ValidDigest(d.NormalizationManifestSHA256) || !delivery.ValidDigest(d.DeliveryManifestSHA256) {
		return invalid()
	}
	if len(d.Pairs) > MaxPairs {
		return limit()
	}
	if len(d.Pairs) == 0 {
		return invalid()
	}
	artifacts, err := inventory(d.ArtifactIDs)
	if err != nil {
		return err
	}
	if d.Scope.Targets == nil {
		return invalid()
	}
	targets := map[string]bool{}
	exclusions := map[string]map[string]bool{}
	for _, t := range d.Scope.Targets {
		if t.Name == "" || targets[t.Name] {
			return invalid()
		}
		targets[t.Name] = true
		excluded, err := inventory(t.Exclude)
		if err != nil {
			return err
		}
		exclusions[t.Name] = excluded
	}
	as, err := selected(d.Scope.ArtifactFilter, artifacts)
	if err != nil {
		return err
	}
	ts, err := selected(d.Scope.TargetFilter, targets)
	if err != nil {
		return err
	}
	// Count expected selected routes without materializing the potentially large
	// artifact/target cross product. Explicit inventory is source-byte bounded.
	expected := 0
	for t := range ts {
		count := len(as)
		for a := range exclusions[t] {
			if as[a] {
				count--
			}
		}
		if count > MaxPairs-expected {
			return limit()
		}
		expected += count
	}
	if expected != len(d.Pairs) {
		return invalid()
	}
	seen := map[string]bool{}
	attempts := map[string]bool{}
	routes := map[string]bool{}
	journals := map[string]bool{}
	for _, p := range d.Pairs {
		route := p.ArtifactID + "\x00" + p.Target
		if !attemptID.MatchString(p.AttemptID) || attempts[p.AttemptID] || !as[p.ArtifactID] || !ts[p.Target] || exclusions[p.Target][p.ArtifactID] || seen[p.ID] || routes[route] || p.JournalPathHint == "" || journals[p.JournalPathHint] {
			return invalid()
		}
		seen[p.ID] = true
		attempts[p.AttemptID] = true
		routes[route] = true
		journals[p.JournalPathHint] = true
		i := p.Intent
		if p.ID != delivery.PairKey(i.Source, i.Destination) || i.Source.ArtifactID != p.ArtifactID || i.Binding != p.Target || i.Destination.DestinationName != p.Target || i.Source.IndexSHA256 != d.Index.SHA256 || i.ConfigSHA256 != d.DeliveryManifestSHA256 || i.Source.AllowFailedGate != d.Scope.AllowFailedGate {
			return invalid()
		}
		if err := record.CheckIntent(i); err != nil {
			return err
		}
	}
	return nil
}
func ValidateIndex(d Descriptor, raw []byte) error {
	if err := Validate(d); err != nil {
		return err
	}
	if delivery.Digest(raw) != d.Index.SHA256 {
		return invalid()
	}
	idx, err := delivery.ParseIndex(raw)
	if err != nil {
		return err
	}
	if d.NormalizationManifestSHA256 != idx.Manifest.SHA256 || len(idx.Artifacts) != len(d.ArtifactIDs) {
		return invalid()
	}
	type facts struct {
		digest, gate string
		schema       bool
	}
	known := map[string]facts{}
	for i, a := range idx.Artifacts {
		if a.ID != d.ArtifactIDs[i] {
			return invalid()
		}
		known[a.ID] = facts{a.Output.SHA256, string(a.Gate), a.SchemaValidated}
	}
	for _, p := range d.Pairs {
		a := known[p.ArtifactID]
		s := p.Intent.Source
		if s.OutputSHA256 != a.digest || s.Gate != a.gate || s.SchemaValidated != a.schema {
			return invalid()
		}
	}
	return nil
}
func ValidateCompletion(c Completion, d Descriptor, batchRaw []byte) error {
	if err := Validate(d); err != nil {
		return err
	}
	parsed, err := ParseDescriptor(batchRaw)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(parsed, d) || c.SchemaVersion != 1 || c.Kind != "rio-delivery-batch-result" || c.BatchSHA256 != delivery.Digest(batchRaw) || len(c.Items) != len(d.Pairs) || c.ErrorCode != "" && !errorCode.MatchString(c.ErrorCode) {
		return invalid()
	}
	switch c.Outcome {
	case "accepted", "partial", "rejected", "unknown", "error":
	default:
		return invalid()
	}
	requested := false
	stopped := false
	accepted := 0
	for i, item := range c.Items {
		if item.AttemptID != "" && item.AttemptID != d.Pairs[i].AttemptID || item.PairID != d.Pairs[i].ID || item.AttemptID != "" && !attemptID.MatchString(item.AttemptID) || item.ErrorCode != "" && !errorCode.MatchString(item.ErrorCode) {
			return invalid()
		}
		if item.Acknowledgment != "" && item.Acknowledgment != "accepted" && item.Acknowledgment != "rejected" && item.Acknowledgment != "unknown" {
			return invalid()
		}
		if item.RequestMayHaveOccurred {
			requested = true
			if item.AttemptID == "" {
				return invalid()
			}
		}
		switch item.State {
		case "unattempted":
			if item.AttemptID != "" || item.Acknowledgment != "" || item.RequestMayHaveOccurred || item.ErrorCode != "" {
				return invalid()
			}
			stopped = true
		case "error":
			if stopped && requested {
				return invalid()
			}
			stopped = true
		case "accepted", "rejected", "unknown":
			if stopped || !item.RequestMayHaveOccurred || item.Acknowledgment != item.State {
				return invalid()
			}
			if item.State == "accepted" && item.ErrorCode == "" {
				accepted++
			} else {
				stopped = true
			}
		default:
			return invalid()
		}
	}
	if c.RequestMayHaveOccurred != requested {
		return invalid()
	}
	if c.Outcome == "accepted" && accepted != len(c.Items) {
		return invalid()
	}
	if c.Outcome == "partial" && (accepted == 0 || accepted == len(c.Items)) {
		return invalid()
	}
	return nil
}

// CheckCompletionJournal compares the immutable original acknowledgment. Later
// reconciliation observations do not replace a submission's disposition.
func CheckCompletionJournal(item CompletionItem, s record.Snapshot) error {
	if len(s.Events) == 0 {
		return invalid()
	}
	if item.State == "unattempted" || item.AttemptID != "" && item.AttemptID != s.Events[0].AttemptID {
		return invalid()
	}
	for _, event := range s.Events {
		if event.Kind == "submission" && (!item.RequestMayHaveOccurred || item.Acknowledgment != "" && item.Acknowledgment != s.Disposition) {
			return invalid()
		}
	}
	return nil
}

// CheckPairJournal enforces exact prepared source/target/policy/payload/retry facts.
func CheckPairJournal(p Pair, s record.Snapshot) error {
	if len(s.Events) == 0 || p.AttemptID != s.Events[0].AttemptID {
		return invalid()
	}
	a, _ := json.Marshal(p.Intent)
	b, _ := json.Marshal(s.Intent)
	if !delivery.JSONEqual(a, b) {
		return invalid()
	}
	return nil
}

// ResolveHint follows only a path explicitly retained by a selected descriptor.
// Portable record inspection never calls this function.
func ValidHint(s string) bool { return s != "" && !strings.ContainsRune(s, 0) }
