// Package record stores immutable delivery evidence; it never constructs clients.
package record

import (
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"regexp"
	"time"
)

const EventLimit int64 = 1 << 20
const MaxEvents = 10000

type Retry struct {
	AttemptID string `json:"attemptId"`
	SHA256    string `json:"sha256"`
	PathHint  string `json:"pathHint,omitempty"`
}
type Intent struct {
	ExpectedReferences []delivery.Reference  `json:"expectedReferences,omitempty"`
	RioVersion         string                `json:"rioVersion"`
	Source             delivery.Source       `json:"source"`
	Payloads           []delivery.PayloadRef `json:"payloads"`
	Binding            string                `json:"binding"`
	Destination        delivery.Description  `json:"destination"`
	ConfigSHA256       string                `json:"configSHA256"`
	Retry              *Retry                `json:"retry,omitempty"`
}
type Reconciliation struct {
	Observation  delivery.Observation `json:"observation"`
	ConfigSHA256 string               `json:"configSHA256"`
}
type Event struct {
	SchemaVersion int             `json:"schemaVersion"`
	Sequence      int             `json:"sequence"`
	AttemptID     string          `json:"attemptId"`
	ObservedAt    string          `json:"observedAt"`
	Kind          string          `json:"kind"`
	Data          json.RawMessage `json:"data"`
}
type Snapshot struct {
	Events       []Event                `json:"events"`
	Intent       Intent                 `json:"intent"`
	SHA256       string                 `json:"sha256"`
	Disposition  string                 `json:"disposition"`
	References   []delivery.Reference   `json:"references"`
	Observations []delivery.Observation `json:"observations"`
	OrphanTemps  []string               `json:"orphanTemps"`
}

var idRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
var codeRE = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

func invalid() error { return delivery.Fail("invalid_record", "journal schema or state") }
func validSource(s delivery.Source) bool {
	return delivery.ValidDigest(s.IndexSHA256) && delivery.ValidDigest(s.OutputSHA256) && s.ArtifactID != "" && (s.Gate == "ok" || s.Gate == "fail") && (s.Gate != "fail" || s.AllowFailedGate)
}
func validateIntent(i Intent) error {
	if i.RioVersion == "" || i.Binding == "" || !validSource(i.Source) || len(i.Payloads) == 0 || !delivery.ValidDigest(i.ConfigSHA256) || i.Destination.Type == "" || i.Destination.DestinationName == "" || len(i.Destination.Capabilities) == 0 {
		return invalid()
	}
	for _, raw := range []json.RawMessage{i.Destination.Identity, i.Destination.Options} {
		var m map[string]json.RawMessage
		if preflight(raw, &m) != nil || delivery.DecodeJSON(raw, &m, false) != nil || m == nil {
			return invalid()
		}
	}
	for _, p := range i.Payloads {
		if p.Role == "" || p.MediaType == "" || !delivery.ValidDigest(p.SHA256) || !delivery.ValidDigest(p.SourceSHA256) || p.Size < 0 || p.Transformation == "" || p.SourceSHA256 != i.Source.OutputSHA256 || (p.Transformation == "identity" && p.SHA256 != p.SourceSHA256) || (p.Size == 0 && p.SHA256 != delivery.Digest(nil)) {
			return invalid()
		}
	}
	if !validReferences(i.ExpectedReferences) {
		return invalid()
	}
	seen := map[delivery.Reference]bool{}
	for _, ref := range i.ExpectedReferences {
		if seen[ref] {
			return invalid()
		}
		seen[ref] = true
	}
	if i.Retry != nil && (!idRE.MatchString(i.Retry.AttemptID) || !delivery.ValidDigest(i.Retry.SHA256)) {
		return invalid()
	}
	return nil
}
func validReferences(rs []delivery.Reference) bool {
	for _, r := range rs {
		if r.Kind == "" || r.Value == "" {
			return false
		}
	}
	return true
}
func validateObservation(o delivery.Observation) error {
	if (o.Origin != "local" && o.Origin != "receiver") || !codeRE.MatchString(o.Code) || !validReferences(o.References) || o.HTTPStatus != 0 && (o.HTTPStatus < 100 || o.HTTPStatus > 599) {
		return invalid()
	}
	switch o.Kind {
	case "acknowledgment":
		if o.Value != "accepted" && o.Value != "rejected" && o.Value != "unknown" {
			return invalid()
		}
	case "activity":
		if o.Value != "processing" && o.Value != "not-observed" {
			return invalid()
		}
	case "unavailable":
		if o.Value != "unavailable" {
			return invalid()
		}
	case "content":
		if o.Value != "verified" && o.Value != "mismatch" && o.Value != "unavailable" {
			return invalid()
		}
	default:
		return invalid()
	}
	if o.Details != nil {
		var m map[string]json.RawMessage
		if delivery.DecodeJSON(o.Details, &m, false) != nil || m == nil {
			return invalid()
		}
	}
	return nil
}
func addEvent(s *Snapshot, e Event) error {
	if e.SchemaVersion != 1 || e.Sequence != len(s.Events) || !idRE.MatchString(e.AttemptID) {
		return invalid()
	}
	tm, err := time.Parse(time.RFC3339Nano, e.ObservedAt)
	if err != nil || tm.Location() != time.UTC {
		return invalid()
	}
	if len(s.Events) > 0 && e.AttemptID != s.Events[0].AttemptID {
		return invalid()
	}
	var model any
	switch e.Kind {
	case "intent":
		model = &Intent{}
	case "submission":
		model = &delivery.Submission{}
	case "reconciliation":
		model = &Reconciliation{}
	default:
		return invalid()
	}
	if err := preflight(e.Data, model); err != nil {
		return err
	}
	switch e.Kind {
	case "intent":
		if len(s.Events) != 0 {
			return invalid()
		}
		var i Intent
		if delivery.DecodeJSON(e.Data, &i, true) != nil || validateIntent(i) != nil {
			return invalid()
		}
		s.Intent = i
		s.Disposition = "unknown"
	case "submission":
		if len(s.Events) != 1 {
			return invalid()
		}
		var sub delivery.Submission
		if delivery.DecodeJSON(e.Data, &sub, true) != nil || !validReferences(sub.References) {
			return invalid()
		}
		if sub.Disposition != "accepted" && sub.Disposition != "rejected" && sub.Disposition != "unknown" {
			return invalid()
		}
		for _, o := range sub.Observations {
			if validateObservation(o) != nil {
				return invalid()
			}
		}
		if sub.Disposition != "unknown" {
			ack := false
			for _, o := range sub.Observations {
				if o.Kind == "acknowledgment" && o.Value == sub.Disposition && o.Origin == "receiver" {
					ack = true
				}
			}
			if !ack {
				return invalid()
			}
		}
		s.Disposition = sub.Disposition
		s.References = sub.References
		s.Observations = append(s.Observations, sub.Observations...)
	case "reconciliation":
		contentRecovery := len(s.Events) >= 1 && delivery.HasCapability(s.Intent.Destination, "observe-content") && len(s.Intent.ExpectedReferences) > 0
		if len(s.Events) < 1 || (len(s.Events) < 2 || s.Events[1].Kind != "submission") && !contentRecovery {
			return invalid()
		}
		var r Reconciliation
		if delivery.DecodeJSON(e.Data, &r, true) != nil || !delivery.ValidDigest(r.ConfigSHA256) || validateObservation(r.Observation) != nil || r.Observation.Kind == "acknowledgment" {
			return invalid()
		}
		if (len(s.Events) == 1 || s.Events[1].Kind != "submission") && r.Observation.Kind != "content" {
			return invalid()
		}
		s.Observations = append(s.Observations, r.Observation)
	default:
		return invalid()
	}
	s.Events = append(s.Events, e)
	return nil
}
