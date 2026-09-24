// Package oci publishes verified snapshots through the explicitly invoked OCI adapter.
package oci

import (
	"encoding/json"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rebaze/rio/internal/delivery"
	"gopkg.in/yaml.v3"
)

const (
	ManifestMediaType             = "application/vnd.oci.image.manifest.v1+json"
	IndexMediaType                = "application/vnd.oci.image.index.v1+json"
	DockerManifestMediaType       = "application/vnd.docker.distribution.manifest.v2+json"
	DockerIndexMediaType          = "application/vnd.docker.distribution.manifest.list.v2+json"
	SBOMMediaType                 = "application/vnd.cyclonedx+json"
	EmptyMediaType                = "application/vnd.oci.empty.v1+json"
	DocumentLimit           int64 = 4 << 20
	ErrorLimit              int64 = 64 << 10
)

type Provider struct{ Directory string }
type Descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}
type Auth struct {
	Anonymous      bool   `json:"anonymous,omitempty"`
	UsernameEnv    string `json:"usernameEnv,omitempty"`
	PasswordEnv    string `json:"passwordEnv,omitempty"`
	BearerTokenEnv string `json:"bearerTokenEnv,omitempty"`
}
type Options struct {
	Registry            string       `json:"registry"`
	Repository          string       `json:"repository"`
	Auth                Auth         `json:"auth"`
	AllowHTTP           bool         `json:"allowHTTP"`
	CAFile              string       `json:"caFile,omitempty"`
	TokenServiceOrigins []string     `json:"tokenServiceOrigins,omitempty"`
	Subject             *Descriptor  `json:"subject,omitempty"`
	Publication         *Publication `json:"publication,omitempty"`
}
type Identity struct {
	Registry   string      `json:"registry"`
	Repository string      `json:"repository"`
	Tag        string      `json:"tag,omitempty"`
	Subject    *Descriptor `json:"subject,omitempty"`
}

var envRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var repoRE = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
var hostRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)

func invalid(field string) error { return delivery.Fail("invalid_oci", field) }
func canonicalRegistry(raw string, plain bool) (string, error) {
	if raw == "" || strings.ContainsAny(raw, "/\\?#@% \t\r\n") {
		return "", invalid("registry authority")
	}
	u, e := url.Parse("https://" + raw)
	if e != nil || u.Hostname() == "" || u.User != nil || u.Path != "" {
		return "", invalid("registry authority")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if strings.Contains(host, ":") {
		if net.ParseIP(host) == nil || !strings.HasPrefix(raw, "[") {
			return "", invalid("registry IPv6")
		}
		host = "[" + host + "]"
	} else if !hostRE.MatchString(host) || strings.Contains(host, "..") {
		return "", invalid("registry host")
	}
	if strings.HasSuffix(raw, ":") {
		return "", invalid("registry port")
	}
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return "", invalid("registry port")
		}
		port = strconv.Itoa(n)
		if plain && port == "80" || !plain && port == "443" {
			port = ""
		}
	}
	if port != "" {
		host += ":" + port
	}
	return host, nil
}
func origin(o Options) string {
	if o.AllowHTTP {
		return "http://" + o.Registry
	}
	return "https://" + o.Registry
}
func canonicalOrigin(raw string, o Options) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return "", invalid("tokenServiceOrigins")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && o.AllowHTTP) {
		return "", invalid("tokenServiceOrigins HTTPS required")
	}
	authority, e := canonicalRegistry(u.Host, u.Scheme == "http")
	if e != nil {
		return "", invalid("tokenServiceOrigins")
	}
	v := u.Scheme + "://" + authority
	if u.Scheme == "http" && v != origin(o) {
		return "", invalid("tokenServiceOrigins HTTP must be registry origin")
	}
	return v, nil
}
func validDescriptor(d Descriptor) bool {
	return strings.HasPrefix(d.Digest, "sha256:") && delivery.ValidDigest(strings.TrimPrefix(d.Digest, "sha256:")) && d.Size > 0 && d.Size <= DocumentLimit && slices.Contains([]string{ManifestMediaType, IndexMediaType, DockerManifestMediaType, DockerIndexMediaType}, d.MediaType)
}
func validateOptions(o Options) error {
	reg, e := canonicalRegistry(o.Registry, o.AllowHTTP)
	if e != nil || reg != o.Registry {
		return invalid("noncanonical registry")
	}
	if len(o.Repository) > 255 || !repoRE.MatchString(o.Repository) {
		return invalid("repository")
	}
	a := o.Auth
	forms := 0
	if a.Anonymous {
		forms++
	}
	if a.UsernameEnv != "" || a.PasswordEnv != "" {
		forms++
		if !envRE.MatchString(a.UsernameEnv) || !envRE.MatchString(a.PasswordEnv) {
			return invalid("auth env references")
		}
	}
	if a.BearerTokenEnv != "" {
		forms++
		if !envRE.MatchString(a.BearerTokenEnv) {
			return invalid("auth env reference")
		}
	}
	if forms != 1 {
		return invalid("auth requires exactly one form")
	}
	if strings.TrimSpace(o.CAFile) != o.CAFile || strings.ContainsAny(o.CAFile, "\x00\r\n") {
		return invalid("caFile reference")
	}
	if o.Subject != nil && !validDescriptor(*o.Subject) {
		return invalid("subject descriptor")
	}
	for i, v := range o.TokenServiceOrigins {
		canonical, e := canonicalOrigin(v, o)
		if e != nil || canonical != v || i > 0 && o.TokenServiceOrigins[i-1] >= v {
			return invalid("noncanonical tokenServiceOrigins")
		}
	}
	return nil
}
func descriptorNode(n yaml.Node) (*Descriptor, error) {
	fields, e := delivery.YAMLMap(n, "digest", "mediaType", "size")
	if e != nil {
		return nil, e
	}
	d := Descriptor{}
	d.Digest, e = delivery.YAMLString(fields["digest"], "subject.digest")
	if e != nil {
		return nil, e
	}
	d.MediaType, e = delivery.YAMLString(fields["mediaType"], "subject.mediaType")
	if e != nil {
		return nil, e
	}
	v := fields["size"]
	if v.Kind != yaml.ScalarNode || v.Tag != "!!int" || v.Decode(&d.Size) != nil || !validDescriptor(d) {
		return nil, invalid("subject descriptor")
	}
	return &d, nil
}
func (p Provider) Describe(destination, binding yaml.Node, _ delivery.Subject) (delivery.Description, error) {
	var d delivery.Description
	dm, e := delivery.YAMLMap(destination, "registry", "repository", "auth", "allowHTTP", "caFile", "tokenServiceOrigins", "subject")
	if e != nil {
		return d, e
	}
	bm, e := delivery.YAMLMap(binding, "subject")
	if e != nil {
		return d, e
	}
	if n, ok := bm["subject"]; ok {
		dm["subject"] = n
	}
	o := Options{}
	if n, ok := dm["allowHTTP"]; ok {
		o.AllowHTTP, e = delivery.YAMLBool(n, "allowHTTP")
		if e != nil {
			return d, e
		}
	}
	raw, e := delivery.YAMLString(dm["registry"], "registry")
	if e != nil {
		return d, e
	}
	o.Registry, e = canonicalRegistry(raw, o.AllowHTTP)
	if e != nil {
		return d, e
	}
	o.Repository, e = delivery.YAMLString(dm["repository"], "repository")
	if e != nil {
		return d, e
	}
	am, e := delivery.YAMLMap(dm["auth"], "anonymous", "usernameEnv", "passwordEnv", "bearerTokenEnv")
	if e != nil {
		return d, e
	}
	if n, ok := am["anonymous"]; ok {
		o.Auth.Anonymous, e = delivery.YAMLBool(n, "auth.anonymous")
		if e != nil || !o.Auth.Anonymous || len(am) != 1 {
			return d, invalid("auth.anonymous")
		}
	}
	for key, dst := range map[string]*string{"usernameEnv": &o.Auth.UsernameEnv, "passwordEnv": &o.Auth.PasswordEnv, "bearerTokenEnv": &o.Auth.BearerTokenEnv} {
		if n, ok := am[key]; ok {
			*dst, e = delivery.YAMLString(n, "auth."+key)
			if e != nil {
				return d, e
			}
		}
	}
	if n, ok := dm["subject"]; ok {
		o.Subject, e = descriptorNode(n)
		if e != nil {
			return d, e
		}
	}
	if n, ok := dm["caFile"]; ok {
		o.CAFile, e = delivery.YAMLString(n, "caFile")
		if e != nil {
			return d, e
		}
		if !filepath.IsAbs(o.CAFile) {
			o.CAFile = filepath.Join(p.Directory, o.CAFile)
		}
	}
	if n, ok := dm["tokenServiceOrigins"]; ok {
		if n.Kind != yaml.SequenceNode || n.Tag != "!!seq" {
			return d, invalid("tokenServiceOrigins list")
		}
		seen := map[string]bool{}
		for _, item := range n.Content {
			raw, e := delivery.YAMLString(*item, "tokenServiceOrigins")
			if e != nil {
				return d, e
			}
			v, e := canonicalOrigin(raw, o)
			if e != nil {
				return d, e
			}
			if seen[v] {
				return d, invalid("duplicate tokenServiceOrigins")
			}
			seen[v] = true
			o.TokenServiceOrigins = append(o.TokenServiceOrigins, v)
		}
		slices.Sort(o.TokenServiceOrigins)
	}
	if e = validateOptions(o); e != nil {
		return d, e
	}
	return description(o, ""), nil
}
func description(o Options, name string) delivery.Description {
	id := Identity{Registry: o.Registry, Repository: o.Repository, Subject: o.Subject}
	if o.Publication != nil {
		id.Tag = o.Publication.Tag
	}
	refs := []string{}
	if o.Auth.UsernameEnv != "" {
		refs = append(refs, o.Auth.UsernameEnv, o.Auth.PasswordEnv)
	}
	if o.Auth.BearerTokenEnv != "" {
		refs = append(refs, o.Auth.BearerTokenEnv)
	}
	caps := []string{"submit", "observe-content"}
	if o.Subject != nil {
		caps = append(caps, "observe-referrers")
	}
	return delivery.Description{Type: "oci", DestinationName: name, Identity: mustJSON(id), Options: mustJSON(o), CredentialRefs: refs, Capabilities: caps}
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// ValidateDescription treats persisted CA references as portable historical strings.
func ValidateDescription(d delivery.Description) (Options, Identity, error) {
	var o Options
	var id Identity
	if d.Type != "oci" {
		return o, id, invalid("adapter type")
	}
	if e := delivery.DecodeJSON(d.Options, &o, true); e != nil {
		return o, id, e
	}
	if e := delivery.DecodeJSON(d.Identity, &id, true); e != nil {
		return o, id, e
	}
	if e := validateOptions(o); e != nil {
		return o, id, e
	}
	if o.Publication != nil {
		if e := validatePublication(o); e != nil {
			return o, id, e
		}
	}
	fresh := description(o, d.DestinationName)
	if !delivery.JSONEqual(fresh.Options, d.Options) || !delivery.JSONEqual(fresh.Identity, d.Identity) || !slices.Equal(fresh.Capabilities, d.Capabilities) || !slices.Equal(fresh.CredentialRefs, d.CredentialRefs) {
		return o, id, invalid("inconsistent description")
	}
	return o, id, nil
}
func SamePolicy(a, b delivery.Description, _ bool) bool {
	ao, _, e := ValidateDescription(a)
	if e != nil {
		return false
	}
	bo, _, e := ValidateDescription(b)
	if e != nil {
		return false
	}
	return delivery.JSONEqual(a.Identity, b.Identity) && ao.AllowHTTP == bo.AllowHTTP && slices.Equal(ao.TokenServiceOrigins, bo.TokenServiceOrigins) && delivery.JSONEqual(mustJSON(ao.Publication), mustJSON(bo.Publication))
}
