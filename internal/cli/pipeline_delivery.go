package cli

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/dtrack"
	"github.com/rebaze/rio/internal/delivery/oci"
	"github.com/rebaze/rio/internal/delivery/runner"
	"github.com/rebaze/rio/internal/receipt"
)

func (r *invocation) describeDeliveries(plan delivery.BatchPlan) error {
	if r.doc.Targets == nil {
		r.doc.Targets = map[string]receipt.Target{}
	}
	previous := r.doc.Deliveries
	r.doc.Deliveries = nil
	for i, j := range plan.Jobs {
		if j.Description.Type == "" {
			if i >= len(previous) || previous[i].ArtifactID != j.ArtifactID || previous[i].Target != j.Target {
				return fmt.Errorf("missing delivery scope")
			}
			r.doc.Deliveries = append(r.doc.Deliveries, previous[i])
			continue
		}
		v := receipt.Delivery{ArtifactID: j.ArtifactID, Target: j.Target, State: "unattempted"}
		target, project, transport, e := compactDestination(j.Description)
		if e != nil {
			return e
		}
		r.doc.Targets[j.Target] = target
		v.Project = project
		v.Transport = transport
		bodies := []delivery.PayloadRef{}
		for _, p := range j.Verified.Payloads() {
			bodies = append(bodies, p.Ref())
		}
		if j.Description.Type == "oci" {
			bodies, e = oci.PublicationBodies(j.Description)
			if e != nil {
				return e
			}
		}
		for _, ref := range bodies {
			v.Intended = append(v.Intended, compactBody(r.doc, j.ArtifactID, ref))
		}

		r.doc.Deliveries = append(r.doc.Deliveries, v)
	}
	if _, e := receipt.Marshal(r.doc); e != nil {
		r.doc.Deliveries = previous
		return e
	}
	return nil
}
func (r *invocation) prepareDeliveries(plan delivery.BatchPlan, prepared []runner.Prepared) error {
	if e := r.describeDeliveries(plan); e != nil {
		return e
	}
	var recovery []struct {
		AttemptID string `json:"attemptId"`
		Journal   string `json:"journal"`
	}
	for i, j := range plan.Jobs {
		id := make([]byte, 16)
		if _, e := rand.Read(id); e != nil {
			return e
		}
		prepared[i].AttemptID = fmt.Sprintf("%x", id)
		r.doc.Deliveries[i].AttemptID = prepared[i].AttemptID
		if prior := prepared[i].Intent.Retry; prior != nil {
			r.doc.Deliveries[i].Prior = &receipt.Prior{AttemptID: prior.AttemptID, SHA256: prior.SHA256}
		}
		recovery = append(recovery, struct {
			AttemptID string `json:"attemptId"`
			Journal   string `json:"journal"`
		}{prepared[i].AttemptID, j.Record})
	}
	raw, e := json.MarshalIndent(recovery, "", "  ")
	if e != nil {
		return e
	}
	if e = r.store.WriteRecovery(raw); e != nil {
		return e
	}
	return r.store.Checkpoint(r.doc)
}

func compactDestination(d delivery.Description) (receipt.Target, map[string]string, receipt.Transport, error) {
	if entry, e := adapter(d.Type); e == nil && entry.CompactDestination != nil {
		return entry.CompactDestination(d)
	}
	target := receipt.Target{Type: d.Type}
	project := map[string]string{}
	transport := receipt.Transport{}
	switch d.Type {
	case "dependency-track":
		opts, id, e := dtrack.ValidateDescription(d)
		if e != nil {
			return target, nil, transport, e
		}
		target.URL = id.URL
		if id.Project.UUID != "" {
			project["uuid"] = id.Project.UUID
		} else {
			project["name"] = id.Project.Name
			project["version"] = id.Project.Version
		}
		transport.CertificateVerification = "enforced"
		if opts.InsecureSkipVerify {
			transport.CertificateVerification = "disabled"
		}
	case "oci":
		var opts oci.Options
		var id oci.Identity
		if e := json.Unmarshal(d.Options, &opts); e != nil {
			return target, nil, transport, e
		}
		if e := json.Unmarshal(d.Identity, &id); e != nil {
			return target, nil, transport, e
		}
		scheme := "https"
		if opts.AllowHTTP {
			scheme = "http"
		}
		target.URL = scheme + "://" + id.Registry
		project["repository"] = id.Repository
		if id.Tag != "" {
			project["tag"] = id.Tag
		}
		if id.Subject != nil {
			project["subject"] = id.Subject.Digest
		}
		transport.CertificateVerification = "enforced"
	default:
		return target, nil, transport, delivery.Fail("unsupported_target", "receipt target")
	}
	transport.Scheme = strings.SplitN(target.URL, ":", 2)[0]
	if transport.Scheme == "http" {
		transport.CertificateVerification = "not-applicable"
	}
	return target, project, transport, nil
}
func (r *invocation) hooks() runner.BatchHooks {
	return runner.BatchHooks{
		Before: func(i int) error {
			r.doc.Run.Stages["delivery"] = "incomplete"
			// A crash after this checkpoint cannot prove the request did not occur.
			// Recovery checks the assigned journal, never replays the upload.
			v := &r.doc.Deliveries[i]
			v.State = "evidence-gap"
			v.RequestMayHaveOccurred = true
			return r.store.Checkpoint(r.doc)
		},
		After: func(i int, one runner.Result) error {
			v := &r.doc.Deliveries[i]
			v.State = one.Outcome
			v.RequestMayHaveOccurred = one.RequestMayHaveOccurred
			v.AttemptedAt = one.AttemptedAt
			if !one.RequestMayHaveOccurred {
				v.State = "error"
			}
			for _, ref := range one.Submitted {
				v.Submitted = append(v.Submitted, compactBody(r.doc, v.ArtifactID, ref))
			}
			if one.Error != nil {
				v.ErrorCode = one.Error.Code
			}
			for _, o := range one.Observations {
				response := receipt.Response{Kind: o.Kind, Value: o.Value, Code: o.Code, HTTPStatus: o.HTTPStatus, ObservedAt: one.ObservedAt}
				for _, ref := range o.References {
					response.References = append(response.References, receipt.Reference{Kind: ref.Kind, Value: ref.Value})
				}
				if e := appendObservation(v, r.doc.Targets[v.Target].Type, o, response); e != nil {
					return e
				}
			}
			return r.store.Checkpoint(r.doc)
		},
	}
}

func compactBody(d receipt.Document, id string, ref delivery.PayloadRef) receipt.Bytes {
	b := receipt.Bytes{SHA256: ref.SHA256, Size: ref.Size, MediaType: ref.MediaType, Role: ref.Role, Transformation: ref.Transformation}
	if ref.Role == "sbom" && ref.Transformation == "identity" {
		for _, a := range d.Artifacts {
			if a.ID == id && a.Output != nil && a.Output.SHA256 == ref.SHA256 && a.Output.Size == ref.Size {
				return receipt.Bytes{ArtifactOutput: id, MediaType: ref.MediaType, Role: ref.Role}
			}
		}
	}
	return b
}
