package index

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/rebaze/rio/internal/transform"
)

// Normalization is an independently versioned optional index-v1 extension.
// Unknown versions retain their bytes but must never be interpreted as version 1.
// Input/output hashes belong to the enclosing artifact, not individual changes.
type Normalization struct {
	Version     int        `json:"version"`
	Changes     []Change   `json:"changes"`
	Bookkeeping []Change   `json:"bookkeeping"`
	Unmapped    []Unmapped `json:"unmapped"`
	Skipped     []Skipped  `json:"skipped"`
	opaque      json.RawMessage
}

type Change struct {
	Target     string                `json:"target"`
	Operation  string                `json:"operation"`
	Rule       string                `json:"rule"`
	Before     any                   `json:"before"`
	After      any                   `json:"after"`
	Resolution *transform.Resolution `json:"resolution,omitempty"`
}
type Unmapped struct {
	Target string `json:"target"`
	Rule   string `json:"rule"`
	PURL   string `json:"purl"`
	Reason string `json:"reason"`
}
type Skipped struct {
	Rule   string `json:"rule"`
	Scope  string `json:"scope"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

func (n *Normalization) UnmarshalJSON(b []byte) error {
	var version struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(b, &version); err != nil {
		return err
	}
	if version.Version != 1 {
		*n = Normalization{Version: version.Version, opaque: append(json.RawMessage(nil), b...)}
		return n.Validate()
	}
	type wire Normalization
	var w wire
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return err
	}
	*n = Normalization(w)
	return n.Validate()
}
func (n Normalization) MarshalJSON() ([]byte, error) {
	if len(n.opaque) > 0 {
		return n.opaque, nil
	}
	type wire Normalization
	return json.Marshal(wire(n))
}

var pointerPattern = regexp.MustCompile(`^(/([^~/]|~[01])*)+$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (n *Normalization) Validate() error {
	if n == nil {
		return nil
	}
	bad := func() error { return fmt.Errorf("invalid normalization extension") }
	if n.Version < 1 {
		return bad()
	}
	if n.Version != 1 {
		return nil
	}
	if n.Changes == nil || n.Bookkeeping == nil || n.Unmapped == nil || n.Skipped == nil {
		return bad()
	}
	for _, list := range [][]Change{n.Changes, n.Bookkeeping} {
		for _, c := range list {
			if !pointerPattern.MatchString(c.Target) || c.Rule == "" {
				return bad()
			}
			switch c.Operation {
			case "add":
				if c.Before != nil {
					return bad()
				}
			case "remove":
				if c.After != nil {
					return bad()
				}
			case "replace":
			default:
				return bad()
			}
			if p := c.Resolution; p != nil {
				if p.Kind == "" || p.Selector == "" || p.SHA256 != "" && !digestPattern.MatchString(p.SHA256) {
					return bad()
				}
				if (p.Kind == "built-in-entry" || p.Kind == "external-table-entry") && p.SHA256 == "" {
					return bad()
				}
				for key := range p.Metadata {
					if key != "confidence" && key != "evidence" {
						return bad()
					}
				}
			}
		}
	}
	for _, u := range n.Unmapped {
		if !pointerPattern.MatchString(u.Target) || u.Rule == "" || u.Reason == "" {
			return bad()
		}
	}
	seen := map[string]bool{}
	for _, s := range n.Skipped {
		key := strings.Join([]string{s.Rule, s.Scope, s.Reason}, "\x00")
		if s.Rule == "" || s.Scope == "" || s.Reason == "" || s.Count <= 0 || seen[key] {
			return bad()
		}
		seen[key] = true
	}
	return nil
}
