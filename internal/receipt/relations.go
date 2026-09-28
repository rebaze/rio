package receipt

import (
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/rebaze/rio/internal/delivery"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func canonicalBody(b Bytes, artifacts map[string]Artifact) Bytes {
	if b.ArtifactOutput != "" {
		a := artifacts[b.ArtifactOutput]
		if a.Output != nil {
			b.SHA256 = a.Output.SHA256
			b.Size = a.Output.Size
		}
		b.ArtifactOutput = ""
	}
	return b
}
func sameBody(expected, actual Bytes, artifacts map[string]Artifact) bool {
	a, b := canonicalBody(expected, artifacts), canonicalBody(actual, artifacts)
	return a.SHA256 == b.SHA256 && a.Size == b.Size && (a.Role == "" || a.Role == b.Role) && (a.MediaType == "" || a.MediaType == b.MediaType) && (a.Transformation == "" || a.Transformation == b.Transformation)
}
func validResponse(r Response) bool {
	switch r.Kind {
	case "acknowledgment":
		return oneOf(r.Value, "accepted", "rejected", "unknown")
	case "content":
		return oneOf(r.Value, "verified", "mismatch", "unavailable")
	case "activity":
		return oneOf(r.Value, "processing", "not-observed")
	case "unavailable":
		return r.Value == "unavailable"
	}
	return false
}
func validReceiverReference(target Target, v Delivery, ref Reference) bool {
	switch target.Type {
	case "dependency-track":
		return ref.Kind == "dependency-track:event-token" && uuidPattern.MatchString(ref.Value)
	case "oci":
		u, e := url.Parse(target.URL)
		if e != nil {
			return false
		}
		base := u.Host + "/" + v.Project["repository"]
		switch ref.Kind {
		case "oci:blob":
			return strings.HasPrefix(ref.Value, "sha256:") && delivery.ValidDigest(strings.TrimPrefix(ref.Value, "sha256:"))
		case "oci:manifest", "oci:subject":
			prefix := base + "@sha256:"
			return v.Project["repository"] != "" && strings.HasPrefix(ref.Value, prefix) && delivery.ValidDigest(strings.TrimPrefix(ref.Value, prefix))
		case "oci:tag":
			return v.Project["tag"] != "" && ref.Value == base+":"+v.Project["tag"]
		default:
			return false
		}
	default:
		return strings.HasPrefix(ref.Kind, target.Type+":") && len(ref.Kind) > len(target.Type)+1 && ref.Value != ""
	}
}
func validateRelations(d Document, artifacts map[string]Artifact) error {
	if err := validateCheckPolicy(d); err != nil {
		return err
	}
	start, _ := time.Parse(time.RFC3339Nano, d.Run.StartedAt)
	finish, _ := time.Parse(time.RFC3339Nano, d.Run.FinishedAt)
	within := func(s string) bool {
		if s == "" {
			return true
		}
		t, e := time.Parse(time.RFC3339Nano, s)
		return e == nil && !t.Before(start) && (finish.IsZero() || !t.After(finish))
	}
	if d.Run.Operation == "normalize" && len(d.Deliveries) > 0 {
		return invalid("normalization invocation includes delivery")
	}
	for _, a := range d.Artifacts {
		if d.Run.Operation == "deliver" && !a.PreExisting {
			return invalid("delivery input scope")
		}
		if d.Run.Outcome == "success" && a.State == "failed" {
			return invalid("success with failed artifact")
		}
	}
	for _, v := range d.Deliveries {
		if v.ProjectSource != "" && (v.ProjectSource != "normalized-subject" || len(v.Project) > 0 || v.RequestMayHaveOccurred && v.State != "evidence-gap") {
			return invalid("unresolved project selector")
		}
		if !within(v.AttemptedAt) {
			return invalid("attempt outside invocation")
		}
		if (len(v.Submitted) > 0 || len(v.Responses) > 0) && !v.RequestMayHaveOccurred {
			return invalid("observations without request")
		}
		if d.Run.Operation == "reconcile" && len(v.Submitted) > 0 {
			return invalid("reconciliation claims upload")
		}
		if d.Run.Outcome == "success" && oneOf(v.State, "unknown", "rejected", "error", "evidence-gap", "unavailable") {
			return invalid("success with unsuccessful delivery")
		}
		for _, sent := range v.Submitted {
			matched := false
			for _, intended := range v.Intended {
				if sameBody(intended, sent, artifacts) {
					matched = true
					break
				}
			}
			if !matched {
				return invalid("submitted bytes not bound to intended bytes")
			}
		}
		ack := false
		attempted, _ := time.Parse(time.RFC3339Nano, v.AttemptedAt)
		for _, r := range v.Responses {
			if !validResponse(r) || !within(r.AttemptedAt) || !within(r.ObservedAt) {
				return invalid("response kind/value/time")
			}
			observed, _ := time.Parse(time.RFC3339Nano, r.ObservedAt)
			request, _ := time.Parse(time.RFC3339Nano, r.AttemptedAt)
			if !observed.IsZero() && ((!attempted.IsZero() && observed.Before(attempted)) || (!request.IsZero() && observed.Before(request))) {
				return invalid("response before request")
			}
			if r.Kind == "acknowledgment" && r.Value == v.State {
				ack = true
			}
			target := d.Targets[v.Target]
			if target.Type == "dependency-track" && r.Kind == "content" || target.Type == "oci" && r.Kind == "activity" {
				return invalid("unsupported receiver observation")
			}
			for _, ref := range r.References {
				if !validReceiverReference(target, v, ref) {
					return invalid("receiver reference identity")
				}
			}
			if target.Type == "dependency-track" && r.Kind == "acknowledgment" && r.Value == "accepted" && (r.HTTPStatus != 200 || len(r.References) != 1) {
				return invalid("Dependency-Track acceptance")
			}
		}
		if oneOf(v.State, "accepted", "rejected") && !ack {
			return invalid("delivery state contradicts acknowledgment")
		}
	}
	return nil
}

// Checks from this invocation enforce one selected-run policy. Standalone
// delivery instead consumes historical checks under its explicit refusal
// override, while reconciliation does not repeat or enforce earlier checks.
func validateCheckPolicy(d Document) error {
	local := oneOf(d.Run.Operation, "pipeline", "normalize")
	blocked, warnFailure := false, false
	localMode := ""
	for _, a := range d.Artifacts {
		c := a.Checks
		if c == nil || a.State == "excluded" {
			continue
		}
		if (c.Gate == "fail" || c.Schema == "fail") && d.Run.Stages["checks"] == "passed" {
			return invalid("passed checks stage contains failed checks")
		}
		if local {
			if c.Mode == "pre-existing" {
				return invalid("local checks described as pre-existing")
			}
			if mode, explicit := d.Run.Overrides["gate"]; explicit && mode != c.Mode {
				return invalid("checks contradict explicit gate policy")
			}
			if localMode != "" && c.Mode != localMode {
				return invalid("conflicting gate policies within invocation")
			}
			localMode = c.Mode
			if c.Schema == "fail" || c.Gate == "fail" && c.Mode == "fail" {
				blocked = true
			}
			warnFailure = warnFailure || c.Gate == "fail" && c.Mode == "warn"
		} else if d.Run.Operation == "deliver" {
			if c.Mode != "pre-existing" {
				return invalid("standalone delivery claims current checks")
			}
			if c.Gate == "fail" && d.Run.Overrides["allow-failed-gate"] != "true" {
				blocked = true
			}
		}
	}
	if local && d.Run.Outcome == "success" && d.Run.Stages["checks"] == "failed" && !warnFailure {
		return invalid("successful invocation has failed checks without warn policy")
	}
	if blocked {
		if d.Run.Outcome == "success" {
			return invalid("successful invocation has enforced check failure")
		}
		for _, v := range d.Deliveries {
			if v.RequestMayHaveOccurred || v.AttemptedAt != "" || len(v.Responses) > 0 || len(v.Submitted) > 0 {
				return invalid("delivery attempted despite enforced check failure")
			}
		}
	}
	return nil
}
