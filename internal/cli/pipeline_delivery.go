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
	r.doc.Deliveries = nil
	for _, j := range plan.Jobs {
		v := receipt.Delivery{ArtifactID: j.ArtifactID, Target: j.Target, State: "unattempted"}
		target, project, transport, e := compactDestination(j.Description)
		if e != nil {
			return e
		}
		r.doc.Targets[j.Target] = target
		v.Project = project
		v.Transport = transport
		for _, p := range j.Verified.Payloads() {
			ref := p.Ref()
			b := receipt.Bytes{SHA256: ref.SHA256, Size: ref.Size, MediaType: ref.MediaType, Role: ref.Role, Transformation: ref.Transformation}
			for _, a := range r.doc.Artifacts {
				if a.ID == j.ArtifactID && a.Output != nil && a.Output.SHA256 == ref.SHA256 && a.Output.Size == ref.Size {
					b = receipt.Bytes{ArtifactOutput: j.ArtifactID}
				}
			}
			v.Intended = append(v.Intended, b)
		}
		r.doc.Deliveries = append(r.doc.Deliveries, v)
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
			} else {
				v.Submitted = append([]receipt.Bytes(nil), v.Intended...)
			}
			if one.Error != nil {
				v.ErrorCode = one.Error.Code
			}
			for _, o := range one.Observations {
				response := receipt.Response{Kind: o.Kind, Value: o.Value, Code: o.Code, HTTPStatus: o.HTTPStatus, ObservedAt: one.ObservedAt}
				for _, ref := range o.References {
					response.References = append(response.References, receipt.Reference{Kind: ref.Kind, Value: ref.Value})
				}
				v.Responses = append(v.Responses, response)
				if one.Destination != nil && one.Destination.Type == "dependency-track" {
					facts, e := dtrack.ReadTLS(o)
					if e != nil {
						return e
					}
					if facts != nil {
						observed := facts.Observed
						v.Transport.TLSObserved = &observed
					}
				}
			}
			return r.store.Checkpoint(r.doc)
		},
	}
}
