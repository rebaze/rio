package oci

import (
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"reflect"
	"slices"
)

// Facts contain only allowlisted protocol/content facts; never server text or URLs.
type Facts struct {
	PublicationBegan bool   `json:"publicationBegan"`
	Phase            string `json:"phase"`
	Manifest         string `json:"manifest,omitempty"`
	Config           string `json:"config,omitempty"`
	Blob             string `json:"blob,omitempty"`
	Tag              string `json:"tag,omitempty"`
	Subject          string `json:"subject,omitempty"`
	Discovery        string `json:"discovery,omitempty"`
}
type details struct {
	OCI Facts `json:"oci"`
}

func observation(kind, value, code string, httpStatus int, facts Facts, refs []delivery.Reference) delivery.Observation {
	if refs == nil {
		refs = []delivery.Reference{}
	}
	origin := "receiver"
	if httpStatus == 0 {
		origin = "local"
	}
	return delivery.Observation{Kind: kind, Value: value, Origin: origin, Code: code, HTTPStatus: httpStatus, References: refs, Details: mustJSON(details{facts})}
}
func ValidateSnapshot(s record.Snapshot) error {
	if e := ValidateIntent(s.Intent); e != nil {
		return e
	}
	expected := s.Intent.ExpectedReferences
	if len(s.References) > 0 && !reflect.DeepEqual(s.References, expected) {
		return invalid("observed references")
	}
	for _, o := range s.Observations {
		if e := validateObservation(o, expected, delivery.HasCapability(s.Intent.Destination, "observe-referrers")); e != nil {
			return e
		}
	}
	for _, event := range s.Events {
		if event.Kind == "submission" {
			var sub delivery.Submission
			if e := delivery.DecodeJSON(event.Data, &sub, true); e != nil {
				return e
			}
			if e := validateSubmission(sub, expected); e != nil {
				return e
			}
		}
	}
	return nil
}
func validateSubmission(sub delivery.Submission, expected []delivery.Reference) error {
	if len(sub.Observations) < 1 || len(sub.Observations) > 2 {
		return invalid("OCI submission observations")
	}
	if sub.Disposition == "accepted" {
		if !reflect.DeepEqual(sub.References, expected) {
			return invalid("accepted references")
		}
	} else if len(sub.References) != 0 {
		return invalid("unaccepted references")
	}
	first := sub.Observations[0]
	switch sub.Disposition {
	case "accepted":
		if first.Kind != "acknowledgment" || first.Value != "accepted" {
			return invalid("accepted acknowledgment")
		}
		switch first.Code {
		case "manifest_accepted":
			if len(sub.Observations) != 1 {
				return invalid("manifest receipt observations")
			}
		case "already_present":
			if len(sub.Observations) != 2 || sub.Observations[1].Kind != "content" || sub.Observations[1].Value != "verified" || !delivery.JSONEqual(first.Details, sub.Observations[1].Details) {
				return invalid("already present requires complete read-back")
			}
		default:
			return invalid("accepted acknowledgment code")
		}
	case "rejected":
		if len(sub.Observations) != 1 || first.Kind != "acknowledgment" || first.Value != "rejected" || first.Code != "upload_rejected" {
			return invalid("rejected acknowledgment")
		}
	case "unknown":
		if len(sub.Observations) != 1 || first.Kind == "acknowledgment" && first.Value == "rejected" || first.Code == "manifest_accepted" || first.Code == "already_present" || first.Value == "verified" {
			return invalid("unknown disposition contradicts observation")
		}
	default:
		return invalid("submission disposition")
	}
	return nil
}
func completeFacts(f Facts, attached bool) bool {
	return f.Manifest == "verified" && f.Config == "verified" && f.Blob == "verified" && f.Tag == "expected" && (!attached || f.Subject == "verified" && f.Discovery == "observed")
}
func validateObservation(o delivery.Observation, expected []delivery.Reference, attached bool) error {
	if o.Kind != "acknowledgment" && o.Kind != "content" {
		return invalid("OCI observation kind")
	}
	if o.HTTPStatus == 0 && o.Origin != "local" || o.HTTPStatus != 0 && o.Origin != "receiver" {
		return invalid("OCI observation origin")
	}
	var d details
	if delivery.PreflightJSON(o.Details, &d, record.JSONEntryLimit) != nil || delivery.DecodeJSON(o.Details, &d, true) != nil {
		return invalid("OCI details")
	}
	f := d.OCI
	if !slices.Contains([]string{"auth", "subject", "referrers", "tag", "config-upload", "sbom-upload", "manifest-upload", "readback"}, f.Phase) {
		return invalid("OCI phase")
	}
	if f.PublicationBegan && slices.Contains([]string{"auth", "subject", "referrers", "tag", "readback"}, f.Phase) || !f.PublicationBegan && f.Phase == "manifest-upload" {
		return invalid("OCI publication phase")
	}
	for _, v := range []string{f.Manifest, f.Config, f.Blob, f.Subject} {
		if v != "" && v != "verified" {
			return invalid("OCI content fact")
		}
	}
	if f.Tag != "" && f.Tag != "expected" && f.Tag != "drift" || f.Discovery != "" && !slices.Contains([]string{"observed", "not-observed", "unavailable"}, f.Discovery) {
		return invalid("OCI content fact")
	}
	if !attached && (f.Subject != "" || f.Discovery != "") {
		return invalid("standalone subject fact")
	}
	if f.Config != "" && f.Manifest != "verified" || f.Blob != "" && f.Config != "verified" || f.Tag != "" && f.Blob != "verified" || f.Subject != "" && f.Tag != "expected" || f.Discovery != "" && f.Subject != "verified" {
		return invalid("OCI read-back ordering")
	}
	if len(o.References) > 0 && !reflect.DeepEqual(o.References, expected) {
		return invalid("OCI observation references")
	}
	if o.Kind == "content" {
		if f.PublicationBegan || !slices.Contains([]string{"readback", "subject", "referrers", "tag"}, f.Phase) {
			return invalid("content phase")
		}
		switch o.Value {
		case "verified":
			if o.Code != "content_verified" || o.HTTPStatus != 200 || f.Phase != "readback" || !completeFacts(f, attached) || !reflect.DeepEqual(o.References, expected) {
				return invalid("OCI verification")
			}
		case "mismatch":
			if !slices.Contains([]string{"content_mismatch", "target_conflict", "tag_drift"}, o.Code) || o.HTTPStatus != 200 || len(o.References) > 0 {
				return invalid("OCI mismatch")
			}
			if o.Code == "target_conflict" && f.Phase != "tag" || o.Code == "tag_drift" && (f.Phase != "readback" || f.Tag != "drift") {
				return invalid("OCI tag mismatch")
			}
		case "unavailable":
			if !slices.Contains([]string{"content_unavailable", "referrers_unavailable", "unsupported_referrers", "invalid_referrers", "unsafe_location", "referrers_limit", "discovery_not_observed", "invalid_references"}, o.Code) || len(o.References) > 0 || f.Discovery == "observed" {
				return invalid("OCI unavailable")
			}
			if o.Code == "unsupported_referrers" && o.HTTPStatus != 404 || o.Code == "discovery_not_observed" && (o.HTTPStatus != 200 || f.Discovery != "not-observed") {
				return invalid("OCI discovery observation")
			}
		default:
			return invalid("content value")
		}
		return nil
	}
	if o.Code != "already_present" && (f.Manifest != "" || f.Config != "" || f.Blob != "" || f.Tag != "" || f.Subject != "" || f.Discovery != "") {
		return invalid("acknowledgment contains content assertion")
	}
	switch o.Value {
	case "accepted":
		switch o.Code {
		case "manifest_accepted":
			if o.HTTPStatus != 201 || !f.PublicationBegan || f.Phase != "manifest-upload" || !reflect.DeepEqual(o.References, expected) {
				return invalid("manifest acknowledgment")
			}
		case "already_present":
			if o.HTTPStatus != 200 || f.PublicationBegan || f.Phase != "readback" || !completeFacts(f, attached) || !reflect.DeepEqual(o.References, expected) {
				return invalid("already present acknowledgment")
			}
		case "unusable_receipt", "unsupported_attachment":
			if o.HTTPStatus != 201 || !f.PublicationBegan || f.Phase != "manifest-upload" || len(o.References) != 0 || o.Code == "unsupported_attachment" && !attached {
				return invalid("unusable receipt observation")
			}
		default:
			return invalid("accepted observation code")
		}
	case "rejected":
		if o.Code != "upload_rejected" || !slices.Contains([]int{400, 401, 403, 404, 405, 409, 413, 415, 422}, o.HTTPStatus) || len(o.References) != 0 {
			return invalid("rejected observation")
		}
	case "unknown":
		if !slices.Contains([]string{"remote_unknown", "transport_unavailable", "auth_scope_refused", "invalid_auth_challenge", "auth_origin_refused", "invalid_auth_response", "invalid_error_response", "response_too_large", "unsafe_location", "unusable_blob_receipt", "invalid_request", "invalid_credentials"}, o.Code) || len(o.References) != 0 {
			return invalid("unknown observation")
		}
	default:
		return invalid("acknowledgment value")
	}
	return nil
}
