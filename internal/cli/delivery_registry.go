package cli

import (
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/dtrack"
	"github.com/rebaze/rio/internal/delivery/record"
)

// This local registry owns adapter policies; core delivery remains HTTP-free.
type adapterEntry struct {
	Provider                   delivery.Provider
	ValidateIntent             func(record.Intent) error
	ValidateSnapshot           func(record.Snapshot) error
	SamePolicy                 func(delivery.Description, delivery.Description, bool) bool
	RecordedSubject            func(delivery.Description) (delivery.Subject, error)
	ValidateObserverReferences func(record.Intent, []delivery.Reference) error
}

var deliveryAdapters = func(dir string) map[string]adapterEntry {
	return map[string]adapterEntry{"dependency-track": {
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
	if ao.AllowHTTP != bo.AllowHTTP {
		return false
	}
	return true
}
