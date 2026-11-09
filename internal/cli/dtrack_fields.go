package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/dtrack"
	"github.com/rebaze/rio/internal/receipt"
)

// requestedProjectFields describes the Dependency-Track project fields a
// delivery will request, before any read-back: every value is unknown.
func requestedProjectFields(d delivery.Description) (*receipt.ProjectFields, error) {
	if d.Type != "dependency-track" {
		return nil, nil
	}
	o, _, e := dtrack.ValidateDescription(d)
	if e != nil {
		return nil, e
	}
	if o.Tags == nil && o.Parent == nil && o.IsLatest == nil {
		return nil, nil
	}
	f := &receipt.ProjectFields{ReadBack: "not-attempted"}
	if o.Tags != nil {
		f.Tags = &receipt.ProjectTagsField{Requested: append([]string(nil), *o.Tags...), State: "unknown"}
	}
	if p := o.Parent; p != nil {
		f.Parent = &receipt.ProjectParentField{Requested: receipt.ProjectParent{UUID: p.UUID, Name: p.Name, Version: p.Version}, State: "unknown"}
	}
	if o.IsLatest != nil {
		f.IsLatest = &receipt.ProjectLatestField{Requested: *o.IsLatest, State: "unknown"}
	}
	return f, nil
}

// observedProjectFields converts the adapter's read-back facts. Both shapes
// share one JSON form; the strict decode refuses any drift between them.
func observedProjectFields(o delivery.Observation) (*receipt.ProjectFields, error) {
	facts, e := dtrack.ReadProject(o)
	if e != nil || facts == nil {
		return nil, e
	}
	raw, _ := json.Marshal(struct {
		ReadBack string             `json:"readBack"`
		Tags     *dtrack.TagsFact   `json:"tags,omitempty"`
		Parent   *dtrack.ParentFact `json:"parent,omitempty"`
		IsLatest *dtrack.LatestFact `json:"isLatest,omitempty"`
	}{facts.ReadBack, facts.Tags, facts.Parent, facts.IsLatest})
	var f receipt.ProjectFields
	if e := delivery.DecodeJSON(raw, &f, true); e != nil {
		return nil, delivery.Fail("invalid_record", "Dependency-Track project facts")
	}
	return &f, nil
}

// describeProjectFields renders requested fields and their states for a human.
func describeProjectFields(f *receipt.ProjectFields) string {
	if f == nil {
		return ""
	}
	var parts []string
	if t := f.Tags; t != nil {
		part := fmt.Sprintf("tags=%s (%s", strings.Join(t.Requested, ","), t.State)
		if t.Observed != nil {
			part += ": " + strings.Join(*t.Observed, ",")
		}
		parts = append(parts, part+")")
	}
	if p := f.Parent; p != nil {
		part := "parent=" + parentLabel(p.Requested) + " (" + p.State
		if p.Observed != nil {
			part += ": " + parentLabel(*p.Observed)
		}
		parts = append(parts, part+")")
	}
	if l := f.IsLatest; l != nil {
		part := fmt.Sprintf("isLatest=%t (%s", l.Requested, l.State)
		if l.Observed != nil {
			part += fmt.Sprintf(": %t", *l.Observed)
		}
		parts = append(parts, part+")")
	}
	if f.ReadBack != "read" {
		parts = append(parts, "readBack="+f.ReadBack)
	}
	return strings.Join(parts, " ")
}

func parentLabel(p receipt.ProjectParent) string {
	switch {
	case p.UUID != "":
		return p.UUID
	case p.Name != "":
		return p.Name + "@" + p.Version
	}
	return "none"
}
