package enrichment

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

// Resolve merges shared defaults and artifact declarations per leaf. Arrays are
// whole leaves. An omitted replace list inherits; an explicit [] clears it.
// artifactSelector is the artifact path, for example "artifacts[0]".
func Resolve(defaults, local *Config, artifactSelector string) (*Resolved, error) {
	if defaults == nil && local == nil {
		return nil, nil
	}
	fields := map[string]Field{}
	var replace *[]string
	var replaceSource string
	for _, layer := range []struct {
		config *Config
		source string
	}{{defaults, "enrichment"}, {local, artifactSelector + ".enrichment"}} {
		if layer.config == nil {
			continue
		}
		values := flatten(layer.config)
		keys := sortedKeys(values)
		for _, key := range keys {
			value := values[key]
			if err := validateValue(key, value); err != nil {
				return nil, fmt.Errorf("%s.%s: %w", layer.source, key, err)
			}
			raw, err := json.Marshal(value)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", layer.source, key, err)
			}
			fields[key] = Field{Field: key, Value: raw, Source: layer.source + "." + key}
		}
		if layer.config.Replace != nil {
			seen := map[string]bool{}
			for _, key := range *layer.config.Replace {
				if !knownField(key) {
					return nil, fmt.Errorf("%s.replace: unknown field %q", layer.source, key)
				}
				if seen[key] {
					return nil, fmt.Errorf("%s.replace: field %q is listed more than once", layer.source, key)
				}
				seen[key] = true
			}
			replace, replaceSource = layer.config.Replace, layer.source
		}
	}
	if replace != nil {
		for _, key := range *replace {
			field, ok := fields[key]
			if !ok {
				return nil, fmt.Errorf("%s.replace: field %q has no effective enrichment value", replaceSource, key)
			}
			field.Replace = true
			fields[key] = field
		}
	}
	out := &Resolved{Version: 1, Fields: make([]Field, 0, len(fields))}
	for _, key := range sortedKeys(fields) {
		out.Fields = append(out.Fields, fields[key])
	}
	return out, nil
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func flatten(config *Config) map[string]any {
	out := map[string]any{}
	add := func(key string, value *string) {
		if value != nil {
			out[key] = *value
		}
	}
	org := func(prefix string, value *Organization) {
		if value == nil {
			return
		}
		add(prefix+".name", value.Name)
		if value.URL != nil {
			out[prefix+".url"] = deduplicate(*value.URL)
		}
		if value.Contact != nil {
			out[prefix+".contact"] = deduplicate(*value.Contact)
		}
	}
	if s := config.Subject; s != nil {
		add("subject.name", s.Name)
		add("subject.group", s.Group)
		add("subject.version", s.Version)
		add("subject.type", s.Type)
		add("subject.purl", s.PURL)
		add("subject.securityContact", s.SecurityContact)
		add("subject.website", s.Website)
		add("subject.documentation", s.Documentation)
		add("subject.support", s.Support)
		org("subject.manufacturer", s.Manufacturer)
		org("subject.supplier", s.Supplier)
	}
	org("producer", config.Producer)
	add("dataLicense", config.DataLicense)
	return out
}

func knownField(key string) bool {
	switch key {
	case "subject.name", "subject.group", "subject.version", "subject.type", "subject.purl", "subject.securityContact", "subject.website", "subject.documentation", "subject.support", "dataLicense":
		return true
	}
	for _, prefix := range []string{"subject.manufacturer", "subject.supplier", "producer"} {
		if key == prefix+".name" || key == prefix+".url" || key == prefix+".contact" {
			return true
		}
	}
	return false
}

var licenseID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+-]*$`)

func validateValue(key string, value any) error {
	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("must be a nonblank string")
		}
		switch key {
		case "subject.type":
			switch v {
			case "application", "container", "cryptographic-asset", "data", "device", "device-driver", "file", "firmware", "framework", "library", "machine-learning-model", "operating-system", "platform":
			default:
				return fmt.Errorf("unknown component type %q", v)
			}
		case "subject.purl":
			if _, err := packageurl.FromString(v); err != nil {
				return fmt.Errorf("must be a valid package URL: %w", err)
			}
		case "subject.website", "subject.documentation", "subject.support":
			return validateURL(v, false)
		case "subject.securityContact":
			return validateURL(v, true)
		case "dataLicense":
			if !licenseID.MatchString(v) {
				return fmt.Errorf("must be one SPDX license identifier, not an expression")
			}
		}
	case []string:
		for i, u := range v {
			if err := validateURL(u, false); err != nil {
				return fmt.Errorf("[%d]: %w", i, err)
			}
		}
	case []Contact:
		for i, c := range v {
			if c.Name == nil && c.Email == nil && c.Phone == nil {
				return fmt.Errorf("[%d]: contact must contain name, email or phone", i)
			}
			for _, field := range []struct {
				name  string
				value *string
			}{{"name", c.Name}, {"email", c.Email}, {"phone", c.Phone}} {
				if field.value == nil {
					continue
				}
				if strings.TrimSpace(*field.value) == "" {
					return fmt.Errorf("[%d].%s: must be a nonblank string", i, field.name)
				}
				if field.name == "email" && !validEmail(*field.value) {
					return fmt.Errorf("[%d].email: must be an email address", i)
				}
			}
		}
	}
	return nil
}

func validEmail(value string) bool {
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Address == value && strings.Contains(value, "@")
}

func validateURL(value string, securityContact bool) error {
	u, err := url.Parse(value)
	if err != nil || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\t ") {
		return fmt.Errorf("must be an absolute HTTP(S) URL%s", contactSuffix(securityContact))
	}
	if securityContact && u.Scheme == "mailto" {
		if u.Host != "" || u.RawQuery != "" || u.Fragment != "" || !validEmail(u.Opaque) {
			return fmt.Errorf("mailto URL must contain one valid email address")
		}
		return nil
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("must be an absolute HTTP(S) URL without credentials%s", contactSuffix(securityContact))
	}
	return nil
}

func contactSuffix(allowed bool) string {
	if allowed {
		return " or mailto email address"
	}
	return ""
}

// deduplicate compares serialized values so contacts with distinct pointers but
// equal optional fields are equal. First occurrence order and empty [] survive.
func deduplicate[T string | Contact](values []T) []T {
	out := make([]T, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		// Both allowed types contain only strings and cannot fail JSON encoding.
		raw, _ := json.Marshal(value)
		key := string(raw)
		if !seen[key] {
			seen[key] = true
			out = append(out, value)
		}
	}
	return out
}
