// Package dtrack implements the explicitly invoked Dependency-Track adapter.
package dtrack

import (
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"gopkg.in/yaml.v3"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

type Provider struct{ Directory string }
type Project struct {
	Name        string `json:"name,omitempty"`
	Version     string `json:"version,omitempty"`
	UUID        string `json:"uuid,omitempty"`
	FromSubject bool   `json:"fromSubject,omitempty"`
}
type Identity struct {
	URL     string  `json:"url"`
	Project Project `json:"project"`
}
type Options struct {
	URL                string  `json:"url"`
	APIKeyEnv          string  `json:"apiKeyEnv"`
	CAFile             string  `json:"caFile,omitempty"`
	AllowHTTP          bool    `json:"allowHTTP"`
	InsecureSkipVerify bool    `json:"insecureSkipVerify,omitempty"`
	Project            Project `json:"project"`
	AutoCreate         *bool   `json:"autoCreate,omitempty"`
	// Tags, Parent and IsLatest are sent with the upload only when configured.
	// Tags replace the project's whole tag set; Parent and IsLatest apply only
	// when the upload creates the project.
	Tags     *[]string `json:"tags,omitempty"`
	Parent   *Parent   `json:"parent,omitempty"`
	IsLatest *bool     `json:"isLatest,omitempty"`
}

// Parent selects an existing parent project by UUID, or by name and an
// optional version; an empty Version selects a version-less project.
type Parent struct {
	UUID    string `json:"uuid,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// projectFieldKeys may be set on the target and replaced per artifact.
var projectFieldKeys = []string{"tags", "parent", "isLatest"}

// maxTag is Dependency-Track's tag name limit.
const maxTag = 255

// describeTags enforces what Dependency-Track 5.2.1 stores unchanged: it splits
// projectTags on commas, trims and lowercases each name, and allows 255
// printable characters. An empty list is refused because a blank projectTags
// changes nothing, so it could never clear the tags it seems to promise to.
func describeTags(n yaml.Node) ([]string, error) {
	bad := delivery.Fail("invalid_config", "tags must be a nonempty list of unique lowercase strings without commas, edge whitespace or control characters, at most 255 characters each")
	if n.Kind != yaml.SequenceNode || n.Tag != "!!seq" || len(n.Content) == 0 {
		return nil, bad
	}
	tags := make([]string, 0, len(n.Content))
	seen := map[string]bool{}
	for _, v := range n.Content {
		tag, e := delivery.YAMLString(*v, "tags")
		if e != nil || seen[tag] || len(tag) > maxTag || strings.Contains(tag, ",") || strings.IndexFunc(tag, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return nil, bad
		}
		if strings.ToLower(tag) != tag {
			return nil, delivery.Fail("invalid_config", "tags must be lowercase; Dependency-Track stores tag names in lowercase")
		}
		seen[tag] = true
		tags = append(tags, tag)
	}
	return tags, nil
}

func describeParent(n yaml.Node) (*Parent, error) {
	pm, e := delivery.YAMLMap(n, "uuid", "name", "version")
	if e != nil {
		return nil, delivery.Fail("invalid_config", "parent must be {uuid} or {name} with an optional version")
	}
	_, uuid := pm["uuid"]
	_, name := pm["name"]
	_, version := pm["version"]
	var p Parent
	switch {
	case uuid && !name && !version:
		if p.UUID, e = delivery.YAMLString(pm["uuid"], "parent.uuid"); e != nil || !ValidUUID(p.UUID) {
			return nil, delivery.Fail("invalid_config", "parent.uuid")
		}
		p.UUID = strings.ToLower(p.UUID)
	case !uuid && name:
		if p.Name, e = delivery.YAMLString(pm["name"], "parent.name"); e != nil {
			return nil, e
		}
		// Without version the parent is a version-less project, as grouping
		// parents usually are; Dependency-Track looks it up with a null version.
		if version {
			if p.Version, e = delivery.YAMLString(pm["version"], "parent.version"); e != nil {
				return nil, e
			}
		}
	default:
		return nil, delivery.Fail("invalid_config", "parent must be exactly one of {uuid} or {name} with an optional version")
	}
	return &p, nil
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var envRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func ValidUUID(s string) bool { return uuidRE.MatchString(s) }
func canonicalURL(s string, allow bool) (string, error) {
	bad := func() (string, error) { return "", delivery.Fail("invalid_config", "destination.url") }
	u, e := url.Parse(s)
	if e != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#") || u.Opaque != "" {
		return bad()
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "https" && (u.Scheme != "http" || !allow) {
		return bad()
	}
	escaped := strings.ToLower(u.EscapedPath())
	if strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") || strings.Contains(u.Path, `\`) {
		return bad()
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return bad()
		}
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port != "" {
		if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
			port = ""
		}
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host = net.JoinHostPort(u.Hostname(), port)
		host = strings.ToLower(host)
	}
	u.Host = host
	u.Path = strings.TrimRight(u.Path, "/")
	if strings.HasSuffix(u.Path, "/api/v1") {
		return "", delivery.Fail("invalid_config", "destination.url must be the server base before /api/v1")
	}
	u.RawPath = ""
	return u.String(), nil
}
func (p Provider) Describe(destination, binding yaml.Node, subject delivery.Subject) (delivery.Description, error) {
	return describe(destination, binding, subject, func(path string) string {
		if !filepath.IsAbs(path) {
			return filepath.Join(p.Directory, path)
		}
		return path
	})
}

// Persisted references are historical strings, not paths on the inspecting host.
// Only current-manifest Describe supplies a host-specific CA resolver.
func describe(destination, binding yaml.Node, subject delivery.Subject, resolveCA func(string) string) (delivery.Description, error) {
	var desc delivery.Description
	dm, e := delivery.YAMLMap(destination, append([]string{"url", "apiKeyEnv", "caFile", "allowHTTP", "insecureSkipVerify", "project", "autoCreate"}, projectFieldKeys...)...)
	if e != nil {
		return desc, e
	}
	bm, e := delivery.YAMLMap(binding, append([]string{"project", "autoCreate"}, projectFieldKeys...)...)
	if e != nil {
		return desc, e
	}
	// Presence survives inheritance: an explicit false is still forbidden for UUID.
	for _, key := range append([]string{"project", "autoCreate"}, projectFieldKeys...) {
		if _, ok := bm[key]; !ok {
			if n, present := dm[key]; present {
				bm[key] = n
			}
		}
	}
	if _, ok := bm["project"]; !ok {
		var n yaml.Node
		n.Encode(map[string]any{"fromSubject": true})
		bm["project"] = n
	}
	o := Options{APIKeyEnv: "DTRACK_API_KEY"}
	if n, ok := dm["allowHTTP"]; ok {
		o.AllowHTTP, e = delivery.YAMLBool(n, "allowHTTP")
		if e != nil {
			return desc, e
		}
	}
	raw, e := delivery.YAMLString(dm["url"], "url")
	if e != nil {
		return desc, e
	}
	o.URL, e = canonicalURL(raw, o.AllowHTTP)
	if e != nil {
		return desc, e
	}
	if n, ok := dm["apiKeyEnv"]; ok {
		o.APIKeyEnv, e = delivery.YAMLString(n, "apiKeyEnv")
		if e != nil {
			return desc, e
		}
	}
	if !envRE.MatchString(o.APIKeyEnv) {
		return desc, delivery.Fail("invalid_config", "apiKeyEnv")
	}
	if n, ok := dm["caFile"]; ok {
		o.CAFile, e = delivery.YAMLString(n, "caFile")
		if e != nil {
			return desc, e
		}
		if resolveCA != nil {
			o.CAFile = resolveCA(o.CAFile)
		}
	}
	if n, ok := dm["insecureSkipVerify"]; ok {
		o.InsecureSkipVerify, e = delivery.YAMLBool(n, "insecureSkipVerify")
		if e != nil {
			return desc, e
		}
	}
	if o.InsecureSkipVerify && (!strings.HasPrefix(o.URL, "https://") || o.CAFile != "") {
		return desc, delivery.Fail("invalid_config", "insecureSkipVerify requires HTTPS and cannot be combined with caFile")
	}
	pm, e := delivery.YAMLMap(bm["project"], "name", "version", "uuid", "fromSubject")
	if e != nil {
		return desc, e
	}
	_, uuid := pm["uuid"]
	_, name := pm["name"]
	_, version := pm["version"]
	_, sub := pm["fromSubject"]
	forms := 0
	for _, v := range []bool{uuid, name || version, sub} {
		if v {
			forms++
		}
	}
	if forms != 1 {
		return desc, delivery.Fail("invalid_config", "project selector")
	}
	if uuid {
		o.Project.UUID, e = delivery.YAMLString(pm["uuid"], "project.uuid")
		if e != nil {
			return desc, e
		}
		if !ValidUUID(o.Project.UUID) {
			return desc, delivery.Fail("invalid_config", "project.uuid")
		}
		o.Project.UUID = strings.ToLower(o.Project.UUID)
		if _, ok := bm["autoCreate"]; ok {
			return desc, delivery.Fail("invalid_config", "autoCreate with uuid")
		}
	} else {
		b := false
		if n, ok := bm["autoCreate"]; ok {
			b, e = delivery.YAMLBool(n, "autoCreate")
			if e != nil {
				return desc, e
			}
		}
		o.AutoCreate = &b
		if sub {
			o.Project.FromSubject, e = delivery.YAMLBool(pm["fromSubject"], "project.fromSubject")
			if e != nil || !o.Project.FromSubject {
				return desc, delivery.Fail("invalid_config", "project.fromSubject must be true")
			}
		} else {
			o.Project.Name, e = delivery.YAMLString(pm["name"], "project.name")
			if e != nil {
				return desc, e
			}
			o.Project.Version, e = delivery.YAMLString(pm["version"], "project.version")
			if e != nil {
				return desc, e
			}
		}
	}
	if n, ok := bm["tags"]; ok {
		tags, e := describeTags(n)
		if e != nil {
			return desc, e
		}
		o.Tags = &tags
	}
	if n, ok := bm["parent"]; ok {
		if o.Parent, e = describeParent(n); e != nil {
			return desc, e
		}
	}
	if n, ok := bm["isLatest"]; ok {
		b, e := delivery.YAMLBool(n, "isLatest")
		if e != nil {
			return desc, e
		}
		o.IsLatest = &b
	}
	// Dependency-Track applies parent and isLatest only while an upload creates
	// the project, which a UUID upload or one without autoCreate never does.
	if (o.Parent != nil || o.IsLatest != nil) && (o.AutoCreate == nil || !*o.AutoCreate) {
		return desc, delivery.Fail("invalid_config", "parent and isLatest require a name/version or fromSubject project with autoCreate: true; Dependency-Track applies them only when the upload creates the project")
	}
	resolved := o.Project
	if sub {
		if subject.Name == "" || subject.Version == "" || strings.TrimSpace(subject.Name) != subject.Name || strings.TrimSpace(subject.Version) != subject.Version {
			return desc, delivery.Fail("invalid_subject", "metadata.component name and version required")
		}
		resolved = Project{Name: subject.Name, Version: subject.Version}
	}
	identity, _ := json.Marshal(Identity{o.URL, resolved})
	options, _ := json.Marshal(o)
	return delivery.Description{Type: "dependency-track", Identity: identity, Options: options, CredentialRefs: []string{o.APIKeyEnv}, Capabilities: []string{"submit", "observe-activity"}}, nil
}

// ValidateDescription validates persisted adapter-owned objects without constructing a client.
func ValidateDescription(d delivery.Description) (Options, Identity, error) {
	var o Options
	var id Identity
	if d.Type != "dependency-track" {
		return o, id, delivery.Fail("invalid_destination", "adapter type")
	}
	if e := delivery.DecodeJSON(d.Options, &o, true); e != nil {
		return o, id, e
	}
	if e := delivery.DecodeJSON(d.Identity, &id, true); e != nil {
		return o, id, e
	}
	// Re-describe canonical typed options to validate every constraint and their relationship.
	dm := map[string]any{"url": o.URL, "apiKeyEnv": o.APIKeyEnv, "allowHTTP": o.AllowHTTP}
	if o.CAFile != "" {
		dm["caFile"] = o.CAFile
	}
	if o.InsecureSkipVerify {
		dm["insecureSkipVerify"] = true
	}
	project := map[string]any{}
	if o.Project.UUID != "" {
		project["uuid"] = o.Project.UUID
	}
	if o.Project.Name != "" {
		project["name"] = o.Project.Name
	}
	if o.Project.Version != "" {
		project["version"] = o.Project.Version
	}
	if o.Project.FromSubject {
		project["fromSubject"] = true
	}
	bm := map[string]any{"project": project}
	if o.AutoCreate != nil {
		bm["autoCreate"] = *o.AutoCreate
	}
	if o.Tags != nil {
		bm["tags"] = *o.Tags
	}
	if o.Parent != nil {
		parent := map[string]any{}
		for k, v := range map[string]string{"uuid": o.Parent.UUID, "name": o.Parent.Name, "version": o.Parent.Version} {
			if v != "" {
				parent[k] = v
			}
		}
		bm["parent"] = parent
	}
	if o.IsLatest != nil {
		bm["isLatest"] = *o.IsLatest
	}
	var dn, bn yaml.Node
	dn.Encode(dm)
	bn.Encode(bm)
	fresh, e := describe(dn, bn, delivery.Subject{Name: id.Project.Name, Version: id.Project.Version}, nil)
	if e != nil {
		return o, id, e
	}
	if !slices.Equal(d.Capabilities, fresh.Capabilities) || !slices.Equal(d.CredentialRefs, fresh.CredentialRefs) {
		return o, id, delivery.Fail("invalid_destination", "capabilities or credential references")
	}
	if string(fresh.Identity) != string(mustJSON(id)) || string(fresh.Options) != string(mustJSON(o)) {
		return o, id, delivery.Fail("invalid_destination", "noncanonical description")
	}
	return o, id, nil
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// CollisionDomain exposes receiver and selector mode without network lookup.
func (p Provider) CollisionDomain(d delivery.Description) (string, string) {
	var id Identity
	if json.Unmarshal(d.Identity, &id) != nil {
		return "", ""
	}
	if id.Project.UUID != "" {
		return id.URL, "uuid"
	}
	return id.URL, "pair"
}
