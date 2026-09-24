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
	URL        string  `json:"url"`
	APIKeyEnv  string  `json:"apiKeyEnv"`
	CAFile     string  `json:"caFile,omitempty"`
	AllowHTTP  bool    `json:"allowHTTP"`
	Project    Project `json:"project"`
	AutoCreate *bool   `json:"autoCreate,omitempty"`
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
	u.RawPath = ""
	return u.String(), nil
}
func (p Provider) Describe(destination, binding yaml.Node, subject delivery.Subject) (delivery.Description, error) {
	var desc delivery.Description
	dm, e := delivery.YAMLMap(destination, "url", "apiKeyEnv", "caFile", "allowHTTP")
	if e != nil {
		return desc, e
	}
	bm, e := delivery.YAMLMap(binding, "project", "autoCreate")
	if e != nil {
		return desc, e
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
		if !filepath.IsAbs(o.CAFile) {
			o.CAFile = filepath.Join(p.Directory, o.CAFile)
		}
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
	var dn, bn yaml.Node
	dn.Encode(dm)
	bn.Encode(bm)
	fresh, e := (Provider{}).Describe(dn, bn, delivery.Subject{Name: id.Project.Name, Version: id.Project.Version})
	if e != nil {
		return o, id, e
	}
	if string(fresh.Identity) != string(mustJSON(id)) || string(fresh.Options) != string(mustJSON(o)) {
		return o, id, delivery.Fail("invalid_destination", "noncanonical description")
	}
	return o, id, nil
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
