package receipt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rebaze/rio/internal/delivery"
)

func invalid(field string) error { return fmt.Errorf("invalid run receipt: %s", field) }
func Parse(raw []byte) (Document, error) {
	var d Document
	if len(raw) > MaxBytes || !utf8.Valid(raw) {
		return d, invalid("byte limit or UTF-8")
	}
	if e := boundJSON(raw); e != nil {
		return d, e
	}
	if err := delivery.DecodeJSON(raw, &d, true); err != nil {
		return d, invalid("schema (expected rio-run-receipt version 1)")
	}
	// The shared decoder intentionally leaves map values opaque; revalidate typed
	// target entries strictly so an unknown field cannot hide inside the map.
	var envelope struct {
		Targets map[string]json.RawMessage `json:"targets"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return d, invalid("schema")
	}
	for _, v := range envelope.Targets {
		var target Target
		if err := delivery.DecodeJSON(v, &target, true); err != nil {
			return d, invalid("target schema")
		}
	}
	return d, Validate(d)
}
func Marshal(d Document) ([]byte, error) {
	if err := Validate(d); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	if b.Len() > MaxBytes {
		return nil, invalid("byte limit")
	}
	if e := boundJSON(b.Bytes()); e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}
func SummarizeValue(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return ValueSummary{Representation: "unavailable"}
	}
	if len(raw) <= MaxValueBytes {
		return v
	}
	return ValueSummary{Representation: "sha256-of-json", SHA256: delivery.Digest(raw), Bytes: len(raw)}
}
func oneOf(s string, choices ...string) bool {
	for _, v := range choices {
		if v == s {
			return true
		}
	}
	return false
}
func timestamp(s string) bool { _, e := time.Parse(time.RFC3339Nano, s); return e == nil }
func validURL(s string) bool {
	u, e := url.Parse(s)
	return e == nil && oneOf(u.Scheme, "https", "http") && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}
func validPrior(p *Prior) bool {
	return p == nil || (delivery.ValidDigest(p.SHA256) && (p.RunID != "" || p.AttemptID != ""))
}
func Validate(d Document) error {
	if d.Kind != Kind || d.SchemaVersion != 1 {
		return invalid("unsupported kind/version; expected rio-run-receipt version 1")
	}
	if d.RioVersion == "" || d.Run.ID == "" || !oneOf(d.Run.Operation, "pipeline", "normalize", "deliver", "reconcile") || !oneOf(d.Run.Outcome, "success", "failed", "partial", "incomplete") || !timestamp(d.Run.StartedAt) || !validPrior(d.Run.Prior) {
		return invalid("run")
	}
	if d.Run.Outcome != "incomplete" && !timestamp(d.Run.FinishedAt) {
		return invalid("finishedAt")
	}
	if d.Run.FinishedAt != "" {
		a, _ := time.Parse(time.RFC3339Nano, d.Run.StartedAt)
		b, e := time.Parse(time.RFC3339Nano, d.Run.FinishedAt)
		if e != nil || b.Before(a) {
			return invalid("run time order")
		}
	}
	if len(d.Run.Stages) == 0 {
		return invalid("stages")
	}
	for k, v := range d.Run.Stages {
		if !oneOf(k, "intake", "normalize", "checks", "delivery") || !oneOf(v, "completed", "passed", "failed", "partial", "not-attempted", "not-configured", "skipped", "incomplete", "pre-existing", "not-applicable") {
			return invalid("stage")
		}
	}
	if len(d.Artifacts) > MaxItems || len(d.Deliveries) > MaxItems || len(d.Targets) > MaxItems || len(d.Exclusions) > MaxItems {
		return invalid("item limit")
	}
	artifacts := map[string]Artifact{}
	checkBytes := func(b Bytes, refs bool) error {
		if b.ArtifactOutput != "" {
			a, ok := artifacts[b.ArtifactOutput]
			if !refs || !ok || a.Output == nil || b.SHA256 != "" || b.Size != 0 || b.Path != "" || b.Transformation != "" && b.Transformation != "identity" {
				return invalid("artifactOutput reference")
			}
		} else if !delivery.ValidDigest(b.SHA256) || b.Size < 0 || b.Size == 0 && b.SHA256 != delivery.Digest(nil) {
			return invalid("byte identity")
		}
		return nil
	}
	for _, a := range d.Artifacts {
		if a.ID == "" || artifacts[a.ID].ID != "" || !oneOf(a.State, "completed", "failed", "not-attempted", "excluded") {
			return invalid("artifact")
		}
		for _, b := range []*Bytes{a.Input, a.Output} {
			if b != nil {
				if e := checkBytes(*b, false); e != nil {
					return e
				}
			}
		}
		if a.State == "completed" && (a.Input == nil || a.Output == nil) {
			return invalid("completed artifact bytes")
		}
		if a.PreExisting && a.Changes != nil {
			return invalid("pre-existing changes attributed to invocation")
		}
		if c := a.Checks; c != nil {
			if !oneOf(c.Mode, "fail", "warn", "pre-existing") || !oneOf(c.Gate, "pass", "fail", "not-evaluated", "not-available") || !oneOf(c.Schema, "pass", "fail", "not-evaluated", "not-available") || !oneOf(c.ComponentEvaluation, "evaluated", "not-evaluated", "not-available") || c.ComponentsEvaluated < 0 || c.Findings < 0 || c.GraphFindings < 0 {
				return invalid("checks")
			}
			if c.ComponentEvaluation == "evaluated" && (len(c.ComponentRequirements) == 0 || c.ComponentsEvaluated == 0) {
				return invalid("empty checks claimed evaluated")
			}
			if c.Gate == "pass" && c.Findings > 0 {
				return invalid("passing gate findings")
			}
		}
		if c := a.Changes; c != nil {
			if len(c.Metadata) > MaxItems || len(c.Bulk) > MaxItems {
				return invalid("change count")
			}
			for _, v := range c.Metadata {
				if v.Field == "" || !oneOf(v.Operation, "add", "replace", "remove") || v.Assertion != "producer" || v.Source == "" {
					return invalid("metadata change")
				}
				for _, value := range []any{v.Before, v.After} {
					raw, e := json.Marshal(value)
					if e != nil || len(raw) > MaxValueBytes {
						return invalid("metadata value must use explicit summary")
					}
				}
				if v.Operation == "add" && v.Before != nil || v.Operation == "remove" && v.After != nil {
					return invalid("change operation")
				}
			}
			for _, v := range c.Bulk {
				if v.Operation == "" || v.Scope == "" || v.Evaluated < 0 || v.Applied < 0 || v.Unmapped < 0 || v.Skipped < 0 {
					return invalid("bulk counters")
				}
				for _, n := range v.Reasons {
					if n < 0 {
						return invalid("bulk reason count")
					}
				}
			}
		}
		artifacts[a.ID] = a
	}
	for label, t := range d.Targets {
		if label == "" || t.Type == "" || !validURL(t.URL) {
			return invalid("target")
		}
	}
	attempts := map[string]bool{}
	for _, v := range d.Deliveries {
		target, ok := d.Targets[v.Target]
		if !ok || artifacts[v.ArtifactID].ID == "" {
			return invalid("delivery reference")
		}
		if !oneOf(v.State, "accepted", "rejected", "unknown", "unattempted", "error", "evidence-gap", "observed", "unavailable") || !validPrior(v.Prior) {
			return invalid("delivery state")
		}
		if v.AttemptID != "" {
			if attempts[v.AttemptID] {
				return invalid("duplicate attempt")
			}
			attempts[v.AttemptID] = true
		}
		if v.AttemptedAt != "" && !timestamp(v.AttemptedAt) {
			return invalid("attempt time")
		}
		if v.State == "unattempted" && (v.RequestMayHaveOccurred || len(v.Submitted) > 0 || len(v.Responses) > 0 || v.AttemptedAt != "") {
			return invalid("unattempted request")
		}
		if oneOf(v.State, "accepted", "rejected") && (!v.RequestMayHaveOccurred || v.AttemptID == "" || len(v.Responses) == 0) {
			return invalid("acknowledgment without attempt")
		}
		for _, list := range [][]Bytes{v.Intended, v.Submitted} {
			if len(list) > MaxItems {
				return invalid("payload count")
			}
			for _, b := range list {
				if e := checkBytes(b, true); e != nil {
					return e
				}
				if b.ArtifactOutput != "" && b.ArtifactOutput != v.ArtifactID {
					return invalid("cross-artifact submission")
				}
			}
		}
		scheme := strings.SplitN(target.URL, ":", 2)[0]
		if v.Transport.Scheme != scheme {
			return invalid("transport scheme")
		}
		if scheme == "http" {
			if v.Transport.TLSObserved != nil || v.Transport.CertificateVerification != "not-applicable" {
				return invalid("HTTP TLS facts")
			}
		} else if !oneOf(v.Transport.CertificateVerification, "enforced", "disabled", "unknown") {
			return invalid("TLS policy")
		}
		if len(v.Responses) > MaxItems {
			return invalid("response count")
		}
		for _, r := range v.Responses {
			if r.Kind == "" || r.Value == "" || r.HTTPStatus != 0 && (r.HTTPStatus < 100 || r.HTTPStatus > 599) || r.ObservedAt != "" && !timestamp(r.ObservedAt) {
				return invalid("response")
			}
			if r.HTTPStatus > 0 && scheme == "https" && v.Transport.TLSObserved != nil && !*v.Transport.TLSObserved {
				return invalid("HTTPS response without TLS")
			}
			if len(r.References) > MaxItems {
				return invalid("reference count")
			}
			for _, ref := range r.References {
				allowed := oneOf(ref.Kind, "dependency-track:event-token", "oci:manifest", "oci:blob", "oci:subject", "oci:tag")
				if !oneOf(target.Type, "dependency-track", "oci") {
					allowed = strings.HasPrefix(ref.Kind, target.Type+":") && len(ref.Kind) > len(target.Type)+1
				}
				if !allowed || ref.Value == "" {
					return invalid("receiver reference")
				}
			}
		}
	}
	return validateRelations(d, artifacts)
}
