package cli

import (
	"encoding/json"
	"fmt"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/dtrack"
	"github.com/rebaze/rio/internal/delivery/oci"
	"github.com/rebaze/rio/internal/delivery/record"
	"strings"
)

// This local registry owns adapter policies; core delivery remains HTTP-free.
type adapterEntry struct {
	HumanIdentityLabel         string
	HumanDescription           func(delivery.Description) string
	HumanTransportPolicy       func(delivery.Description) string
	HumanObservation           func(delivery.Observation) string
	Provider                   delivery.Provider
	ValidateIntent             func(record.Intent) error
	ValidateSnapshot           func(record.Snapshot) error
	SamePolicy                 func(delivery.Description, delivery.Description, bool) bool
	RecordedSubject            func(delivery.Description) (delivery.Subject, error)
	ValidateObserverReferences func(record.Intent, []delivery.Reference) error
}

var deliveryAdapters = func(dir string) map[string]adapterEntry {
	return map[string]adapterEntry{"oci": {
		HumanObservation: func(o delivery.Observation) string {
			var d struct {
				OCI oci.Facts `json:"oci"`
			}
			if delivery.DecodeJSON(o.Details, &d, true) != nil {
				return ""
			}
			f := d.OCI
			parts := []string{fmt.Sprintf("publicationBegan=%t phase=%s", f.PublicationBegan, f.Phase)}
			for _, item := range [][2]string{{"manifest", f.Manifest}, {"config", f.Config}, {"blob", f.Blob}, {"tag", f.Tag}, {"subject", f.Subject}, {"discovery", f.Discovery}} {
				if item[1] != "" {
					parts = append(parts, item[0]+"="+item[1])
				}
			}
			return strings.Join(parts, " ")
		},
		Provider: oci.Provider{Directory: dir}, ValidateIntent: oci.ValidateIntent,
		ValidateSnapshot: oci.ValidateSnapshot, SamePolicy: oci.SamePolicy,
		RecordedSubject:            func(delivery.Description) (delivery.Subject, error) { return delivery.Subject{}, nil },
		ValidateObserverReferences: oci.ValidateObserverReferences,
	}, "dependency-track": {
		HumanIdentityLabel:   "project",
		HumanTransportPolicy: dtrackTransportPolicy,
		HumanObservation: func(o delivery.Observation) string {
			facts, e := dtrack.ReadTLS(o)
			if e != nil || facts == nil {
				return ""
			}
			return fmt.Sprintf("certificateVerification=%s TLSObserved=%t", facts.CertificateVerification, facts.Observed)
		},
		HumanDescription: func(d delivery.Description) string {
			o, id, e := dtrack.ValidateDescription(d)
			if e != nil {
				return ""
			}
			if id.Project.UUID != "" {
				return " autoCreate=not-applicable" + dtrackTransportPolicy(d)
			}
			if o.AutoCreate != nil {
				return fmt.Sprintf(" autoCreate=%t", *o.AutoCreate) + dtrackTransportPolicy(d)
			}
			return ""
		},
		Provider: dtrack.Provider{Directory: dir},
		ValidateIntent: func(i record.Intent) error {
			if len(i.ExpectedReferences) > 0 {
				return delivery.Fail("invalid_record", "unexpected references")
			}
			_, _, e := dtrack.ValidateDescription(i.Destination)
			return e
		},
		ValidateSnapshot: validateDTrackSnapshot,
		SamePolicy:       sameDTrackPolicy,
		RecordedSubject: func(d delivery.Description) (delivery.Subject, error) {
			_, id, e := dtrack.ValidateDescription(d)
			return delivery.Subject{Name: id.Project.Name, Version: id.Project.Version}, e
		},
		ValidateObserverReferences: func(_ record.Intent, rs []delivery.Reference) error { _, e := dtrack.EventToken(rs); return e },
	}}
}

func providers(dir string) map[string]delivery.Provider {
	ps := map[string]delivery.Provider{}
	for kind, entry := range deliveryAdapters(dir) {
		ps[kind] = entry.Provider
	}
	return ps
}
func adapter(kind string) (adapterEntry, error) {
	a, ok := deliveryAdapters("")[kind]
	if !ok {
		return a, delivery.Fail("unsupported_adapter", "journal destination type")
	}
	return a, nil
}
func validateSnapshot(s record.Snapshot) error {
	a, e := adapter(s.Intent.Destination.Type)
	if e != nil {
		return e
	}
	if e = a.ValidateIntent(s.Intent); e != nil {
		return e
	}
	return a.ValidateSnapshot(s)
}
func samePolicy(a, b delivery.Description, reconcile bool) bool {
	entry, e := adapter(a.Type)
	return e == nil && a.Type == b.Type && entry.SamePolicy(a, b, reconcile)
}
func validateDTrackSnapshot(s record.Snapshot) error {
	if _, _, e := dtrack.ValidateDescription(s.Intent.Destination); e != nil {
		return e
	}
	for _, event := range s.Events {
		if event.Kind == "submission" {
			var sub delivery.Submission
			if e := delivery.DecodeJSON(event.Data, &sub, true); e != nil {
				return e
			}
			if e := dtrack.ValidateSubmission(sub); e != nil {
				return e
			}
		}
	}
	if e := dtrack.ValidateTransport(s.Intent.Destination, s.Observations); e != nil {
		return e
	}
	return dtrack.ValidateEvidence(s.References, s.Observations)
}
func sameDTrackPolicy(a, b delivery.Description, reconcile bool) bool {
	ao, ai, e := dtrack.ValidateDescription(a)
	if e != nil {
		return false
	}
	bo, bi, e := dtrack.ValidateDescription(b)
	if e != nil {
		return false
	}
	ab, _ := json.Marshal(ai)
	bb, _ := json.Marshal(bi)
	if string(ab) != string(bb) || a.Type != b.Type || ao.Project != bo.Project {
		return false
	}
	if (ao.AutoCreate == nil) != (bo.AutoCreate == nil) {
		return false
	}
	if ao.AutoCreate != nil && *ao.AutoCreate != *bo.AutoCreate {
		return false
	}
	if ao.AllowHTTP != bo.AllowHTTP || ao.InsecureSkipVerify != bo.InsecureSkipVerify {
		return false
	}
	return true
}

func dtrackTransportPolicy(d delivery.Description) string {
	o, _, e := dtrack.ValidateDescription(d)
	if e != nil || !o.InsecureSkipVerify {
		return ""
	}
	return " insecureSkipVerify=true (certificate verification disabled)"
}
