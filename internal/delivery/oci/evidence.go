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
	if len(sub.References) > 0 && !reflect.DeepEqual(sub.References, expected) {
		return invalid("submission references")
	}
	validAck := false
	for _, o := range sub.Observations {
		if o.Kind == "acknowledgment" && o.Value == sub.Disposition {
			if sub.Disposition == "accepted" {
				validAck = validAck || o.Code == "manifest_accepted" || o.Code == "already_present"
			} else if sub.Disposition == "rejected" {
				validAck = validAck || o.Code == "upload_rejected"
			}
		}
	}
	if sub.Disposition != "unknown" && !validAck {
		return invalid("submission acknowledgment")
	}
	if sub.Disposition == "accepted" && !reflect.DeepEqual(sub.References, expected) {
		return invalid("accepted references")
	}
	if sub.Disposition != "accepted" && len(sub.References) > 0 {
		return invalid("unaccepted references")
	}
	return nil
}
func validateObservation(o delivery.Observation, expected []delivery.Reference, attached bool) error {
	if o.Kind != "acknowledgment" && o.Kind != "content" {
		return invalid("OCI observation kind")
	}
	var d details
	if delivery.DecodeJSON(o.Details, &d, true) != nil {
		return invalid("OCI details")
	}
	f := d.OCI
	if !slices.Contains([]string{"auth", "subject", "referrers", "tag", "config-upload", "sbom-upload", "manifest-upload", "readback"}, f.Phase) {
		return invalid("OCI phase")
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
	if len(o.References) > 0 && !reflect.DeepEqual(o.References, expected) {
		return invalid("OCI observation references")
	}
	if o.Value == "verified" {
		if o.Kind != "content" || o.Code != "content_verified" || o.HTTPStatus != 200 || f.Manifest != "verified" || f.Config != "verified" || f.Blob != "verified" || f.Tag != "expected" || attached && (f.Subject != "verified" || f.Discovery != "observed") || !reflect.DeepEqual(o.References, expected) {
			return invalid("OCI verification")
		}
	}
	if o.Kind == "acknowledgment" && o.Value == "accepted" {
		switch o.Code {
		case "manifest_accepted":
			if o.HTTPStatus != 201 || !f.PublicationBegan || f.Phase != "manifest-upload" || !reflect.DeepEqual(o.References, expected) {
				return invalid("manifest acknowledgment")
			}
		case "already_present":
			if o.HTTPStatus != 200 || f.PublicationBegan || f.Manifest != "verified" || f.Blob != "verified" {
				return invalid("already present acknowledgment")
			}
		case "unusable_receipt", "unsupported_attachment":
			if o.HTTPStatus != 201 || !f.PublicationBegan || len(o.References) != 0 {
				return invalid("unusable receipt observation")
			}
		default:
			return invalid("accepted observation code")
		}
	}
	return nil
}
