package dtrack

import (
	"context"
	"encoding/json"
	"mime/multipart"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/rebaze/rio/internal/delivery"
)

// ProjectFacts record the requested project fields and what a read-back of the
// project observed after the upload. A value is "observed" when the read-back
// shows it, "different" when it shows another value, and "unknown" when the
// project could not be read. Nothing is ever recorded as applied unseen.
type ProjectFacts struct {
	// ReadBack is "read", or why the project could not be read: "forbidden"
	// (401/403, usually no VIEW_PORTFOLIO), "not-found", "transient",
	// "unexpected-status", "unavailable" (no response) or "invalid-response".
	ReadBack   string      `json:"readBack"`
	HTTPStatus int         `json:"httpStatus,omitempty"`
	Tags       *TagsFact   `json:"tags,omitempty"`
	Parent     *ParentFact `json:"parent,omitempty"`
	IsLatest   *LatestFact `json:"isLatest,omitempty"`
}

// The observed value is kept only when it differs from the requested one.
type TagsFact struct {
	Requested []string  `json:"requested"`
	State     string    `json:"state"`
	Observed  *[]string `json:"observed,omitempty"`
}
type ParentFact struct {
	Requested Parent  `json:"requested"`
	State     string  `json:"state"`
	Observed  *Parent `json:"observed,omitempty"`
}
type LatestFact struct {
	Requested bool   `json:"requested"`
	State     string `json:"state"`
	Observed  *bool  `json:"observed,omitempty"`
}

// requestsProjectFields reports whether the upload carries any project field.
func (o Options) requestsProjectFields() bool {
	return o.Tags != nil || o.Parent != nil || o.IsLatest != nil
}

// writeProjectFields adds the configured fields to the upload form, and only
// those, so targets without them send exactly what they always sent.
func (o Options) writeProjectFields(mw *multipart.Writer) {
	if o.Tags != nil {
		mw.WriteField("projectTags", strings.Join(*o.Tags, ","))
	}
	if p := o.Parent; p != nil {
		if p.UUID != "" {
			mw.WriteField("parentUUID", p.UUID)
		} else {
			mw.WriteField("parentName", p.Name)
			if p.Version != "" {
				mw.WriteField("parentVersion", p.Version)
			}
		}
	}
	if o.IsLatest != nil {
		mw.WriteField("isLatest", strconv.FormatBool(*o.IsLatest))
	}
}

// matches compares an observed parent by the requested selector: its UUID, or
// its name and version.
func (p Parent) matches(got Parent) bool {
	if p.UUID != "" {
		return strings.EqualFold(got.UUID, p.UUID)
	}
	return got.Name == p.Name && got.Version == p.Version
}

// parentSelector names the configured parent for a failure message.
func (p Parent) selector() string {
	if p.UUID != "" {
		return "parent uuid=" + p.UUID
	}
	if p.Version == "" {
		return "parent name=" + p.Name + " (no version)"
	}
	return "parent name=" + p.Name + " version=" + p.Version
}

// unread is the facts for a project that could not be read back.
func (o Options) unread(code string, status int) *ProjectFacts {
	f := &ProjectFacts{ReadBack: code, HTTPStatus: status}
	if o.Tags != nil {
		f.Tags = &TagsFact{Requested: slices.Clone(*o.Tags), State: "unknown"}
	}
	if o.Parent != nil {
		f.Parent = &ParentFact{Requested: *o.Parent, State: "unknown"}
	}
	if o.IsLatest != nil {
		f.IsLatest = &LatestFact{Requested: *o.IsLatest, State: "unknown"}
	}
	return f
}

// projectDocument holds the read-back fields compared; nothing else is kept.
type projectDocument struct {
	UUID string `json:"uuid"`
	Tags []struct {
		Name string `json:"name"`
	} `json:"tags"`
	Parent *struct {
		UUID    string `json:"uuid"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"parent"`
	IsLatest *bool `json:"isLatest"`
}

// getProject reads one project document, or the facts explaining why not.
func (c *client) getProject(ctx context.Context, path string) (projectDocument, *ProjectFacts) {
	var project projectDocument
	o := c.options
	resp, _, e := c.request(ctx, "GET", path, "", nil)
	if e != nil {
		return project, o.unread("unavailable", 0)
	}
	defer resp.Body.Close()
	switch status := resp.StatusCode; {
	case status == 401 || status == 403:
		return project, o.unread("forbidden", status)
	case status == 404:
		return project, o.unread("not-found", status)
	case status == 429 || status >= 500:
		return project, o.unread("transient", status)
	case status != 200:
		return project, o.unread("unexpected-status", status)
	}
	body, e := responseBytes(resp, projectLimit)
	// A document without a project UUID, such as null or {}, is not a project.
	if e != nil || json.Unmarshal(body, &project) != nil || !ValidUUID(project.UUID) || (o.IsLatest != nil && project.IsLatest == nil) {
		return project, o.unread("invalid-response", 200)
	}
	return project, nil
}

// readProject reads the project back: by UUID, or by name and version, which
// Dependency-Track serves only to a key with VIEW_PORTFOLIO. The lookup by
// name omits the parent, so a requested parent is read from the project by
// UUID. Only the fields compared are decoded; the body is never retained.
func (c *client) readProject(ctx context.Context) *ProjectFacts {
	o := c.options
	p := c.identity.Project
	uuid := p.UUID
	var project projectDocument
	if uuid == "" {
		var failed *ProjectFacts
		if project, failed = c.getProject(ctx, "/api/v1/project/lookup?"+url.Values{"name": {p.Name}, "version": {p.Version}}.Encode()); failed != nil {
			return failed
		}
		if o.Parent != nil {
			if !ValidUUID(project.UUID) {
				return o.unread("invalid-response", 200)
			}
			uuid = strings.ToLower(project.UUID)
		}
	}
	if uuid != "" {
		var failed *ProjectFacts
		if project, failed = c.getProject(ctx, "/api/v1/project/"+uuid); failed != nil {
			return failed
		}
	}
	f := &ProjectFacts{ReadBack: "read", HTTPStatus: 200}
	if o.Tags != nil {
		observed := make([]string, 0, len(project.Tags))
		for _, t := range project.Tags {
			observed = append(observed, t.Name)
		}
		f.Tags = &TagsFact{Requested: slices.Clone(*o.Tags), State: "observed"}
		if !sameSet(*o.Tags, observed) {
			slices.Sort(observed)
			f.Tags.State, f.Tags.Observed = "different", &observed
		}
	}
	if o.Parent != nil {
		f.Parent = &ParentFact{Requested: *o.Parent, State: "observed"}
		var got Parent
		if project.Parent != nil {
			got = Parent{UUID: strings.ToLower(project.Parent.UUID), Name: project.Parent.Name, Version: project.Parent.Version}
		}
		if project.Parent == nil || !o.Parent.matches(got) {
			f.Parent.State, f.Parent.Observed = "different", &got
		}
	}
	if o.IsLatest != nil {
		f.IsLatest = &LatestFact{Requested: *o.IsLatest, State: "observed"}
		if *project.IsLatest != *o.IsLatest {
			f.IsLatest.State, f.IsLatest.Observed = "different", project.IsLatest
		}
	}
	return f
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

// observationDetails is the adapter-owned detail object of an observation.
type observationDetails struct {
	TLS     *TLSFacts     `json:"tls,omitempty"`
	Project *ProjectFacts `json:"project,omitempty"`
}

func readDetails(o delivery.Observation) (observationDetails, error) {
	var d observationDetails
	if o.Details == nil {
		return d, nil
	}
	if delivery.DecodeJSON(o.Details, &d, true) != nil {
		return d, delivery.Fail("invalid_record", "Dependency-Track observation details")
	}
	return d, nil
}

func setDetails(o *delivery.Observation, d observationDetails) {
	if d.TLS == nil && d.Project == nil {
		o.Details = nil
		return
	}
	o.Details, _ = json.Marshal(d)
}

// attachProject keeps the facts beside any TLS details of the observation.
func attachProject(o *delivery.Observation, f *ProjectFacts) {
	d, _ := readDetails(*o)
	d.Project = f
	setDetails(o, d)
}

// ReadProject returns the project facts an observation carries, if any.
func ReadProject(o delivery.Observation) (*ProjectFacts, error) {
	d, e := readDetails(o)
	if e != nil {
		return nil, e
	}
	if d.Project != nil {
		if e := d.Project.validate(); e != nil {
			return nil, e
		}
	}
	return d.Project, nil
}

var readBackCodes = []string{"read", "forbidden", "not-found", "transient", "unexpected-status", "unavailable", "invalid-response"}

// validate refuses facts this adapter cannot produce: a state that the
// read-back contradicts, an observed value kept without a difference, or a
// claim beyond observed, different or unknown.
func (f ProjectFacts) validate() error {
	bad := delivery.Fail("invalid_record", "Dependency-Track project facts")
	if !slices.Contains(readBackCodes, f.ReadBack) || (f.Tags == nil && f.Parent == nil && f.IsLatest == nil) {
		return bad
	}
	read := f.ReadBack == "read"
	switch f.ReadBack {
	case "read", "invalid-response":
		if f.HTTPStatus != 200 {
			return bad
		}
	case "forbidden":
		if f.HTTPStatus != 401 && f.HTTPStatus != 403 {
			return bad
		}
	case "not-found":
		if f.HTTPStatus != 404 {
			return bad
		}
	case "transient":
		if f.HTTPStatus != 429 && f.HTTPStatus < 500 {
			return bad
		}
	case "unexpected-status":
		if f.HTTPStatus < 100 || f.HTTPStatus > 599 || slices.Contains([]int{200, 401, 403, 404, 429}, f.HTTPStatus) || f.HTTPStatus >= 500 {
			return bad
		}
	case "unavailable":
		if f.HTTPStatus != 0 {
			return bad
		}
	}
	state := func(s string, hasObserved bool) bool {
		switch s {
		case "observed":
			return read && !hasObserved
		case "different":
			return read && hasObserved
		case "unknown":
			return !read && !hasObserved
		}
		return false
	}
	if t := f.Tags; t != nil {
		if len(t.Requested) == 0 || !state(t.State, t.Observed != nil) {
			return bad
		}
		if t.Observed != nil && sameSet(t.Requested, *t.Observed) {
			return bad
		}
	}
	if p := f.Parent; p != nil {
		if (p.Requested.UUID == "") == (p.Requested.Name == "") || !state(p.State, p.Observed != nil) || p.Observed != nil && p.Requested.matches(*p.Observed) {
			return bad
		}
	}
	if l := f.IsLatest; l != nil {
		if !state(l.State, l.Observed != nil) || l.Observed != nil && *l.Observed == l.Requested {
			return bad
		}
	}
	return nil
}

// requested strips the observations, leaving what the intent asked for.
func (f ProjectFacts) requested() (tags *[]string, parent *Parent, latest *bool) {
	if f.Tags != nil {
		tags = &f.Tags.Requested
	}
	if f.Parent != nil {
		parent = &f.Parent.Requested
	}
	if f.IsLatest != nil {
		latest = &f.IsLatest.Requested
	}
	return
}

// matchesIntent binds recorded requested values to the persisted options.
func (f ProjectFacts) matchesIntent(o Options) bool {
	tags, parent, latest := f.requested()
	return reflect.DeepEqual(tags, o.Tags) && reflect.DeepEqual(parent, o.Parent) && reflect.DeepEqual(latest, o.IsLatest)
}
