package delivery

import (
	"gopkg.in/yaml.v3"
	"regexp"
	"strings"
)

type Config struct {
	Directory string
	SHA256    string
	Targets   map[string]TargetConfig
}

// YAMLMap rejects aliases, merge keys, duplicate/non-string keys and unknown keys.
func YAMLMap(n yaml.Node, allowed ...string) (map[string]yaml.Node, error) {
	if n.Kind != yaml.MappingNode || n.Tag != "!!map" {
		return nil, Fail("invalid_config", "mapping required")
	}
	m := map[string]yaml.Node{}
	for i := 0; i < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "" {
			return nil, Fail("invalid_config", "mapping key")
		}
		if _, ok := m[k.Value]; ok {
			return nil, Fail("invalid_config", "duplicate key")
		}
		if allowed != nil {
			found := false
			for _, a := range allowed {
				found = found || a == k.Value
			}
			if !found {
				return nil, Fail("invalid_config", "unknown field")
			}
		}
		m[k.Value] = *v
	}
	return m, nil
}
func YAMLString(n yaml.Node, field string) (string, error) {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" || n.Value == "" || strings.TrimSpace(n.Value) != n.Value {
		return "", Fail("invalid_config", field+" requires nonempty string without edge whitespace")
	}
	return n.Value, nil
}
func YAMLBool(n yaml.Node, field string) (bool, error) {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!bool" {
		return false, Fail("invalid_config", field+" requires boolean")
	}
	var b bool
	if n.Decode(&b) != nil {
		return false, Fail("invalid_config", field)
	}
	return b, nil
}

// TargetConfig holds a flat declaration; no credentials or files are resolved here.
type TargetConfig struct {
	Type      string
	Options   yaml.Node
	Exclude   []string
	Overrides map[string]yaml.Node
}

var targetID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

func validateYAML(n yaml.Node, depth int, size *int64) error {
	if depth > 100 || n.Kind == yaml.AliasNode || n.Anchor != "" {
		return Fail("invalid_config", "delivery aliases or depth")
	}
	*size += int64(len(n.Value) + len(n.HeadComment) + len(n.LineComment) + len(n.FootComment))
	if *size > ConfigLimit {
		return Fail("size_limit", "delivery declaration")
	}
	if n.Kind == yaml.MappingNode {
		if _, e := YAMLMap(n); e != nil {
			return e
		}
	}
	for _, c := range n.Content {
		if e := validateYAML(*c, depth+1, size); e != nil {
			return e
		}
	}
	return nil
}

// ParseConfig consumes the delivery node captured from one raw rio.yaml snapshot.
// Common shape validation stays independent of concrete adapters and network clients.
func ParseConfig(n yaml.Node, directory, sha256 string) (Config, error) {
	c := Config{Directory: directory, SHA256: sha256, Targets: map[string]TargetConfig{}}
	if n.IsZero() {
		return c, nil
	}
	var size int64
	if e := validateYAML(n, 0, &size); e != nil {
		return c, e
	}
	encoded, e := yaml.Marshal(n)
	if e != nil {
		return c, Fail("invalid_config", "delivery declaration")
	}
	if int64(len(encoded)) > ConfigLimit {
		return c, Fail("size_limit", "delivery declaration")
	}
	root, e := YAMLMap(n, "targets")
	if e != nil {
		return c, e
	}
	ts, e := YAMLMap(root["targets"])
	if e != nil {
		return c, e
	}
	if len(ts) == 0 {
		return c, Fail("invalid_config", "delivery.targets must not be empty")
	}
	for id, n := range ts {
		if !targetID.MatchString(id) {
			return c, Fail("invalid_config", "delivery target id")
		}
		fields, e := YAMLMap(n)
		if e != nil {
			return c, e
		}
		typ, e := YAMLString(fields["type"], "target.type")
		if e != nil {
			return c, e
		}
		t := TargetConfig{Type: typ, Overrides: map[string]yaml.Node{}}
		t.Options = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		for i := 0; i < len(n.Content); i += 2 {
			if k := n.Content[i].Value; k != "type" && k != "exclude" && k != "overrides" {
				t.Options.Content = append(t.Options.Content, n.Content[i], n.Content[i+1])
			}
		}
		if ex, ok := fields["exclude"]; ok {
			if ex.Kind != yaml.SequenceNode || ex.Tag != "!!seq" {
				return c, Fail("invalid_config", "target.exclude list required")
			}
			seen := map[string]bool{}
			for _, v := range ex.Content {
				id, e := YAMLString(*v, "exclude artifact id")
				if e != nil || !targetID.MatchString(id) || seen[id] {
					return c, Fail("invalid_config", "target.exclude artifact id")
				}
				seen[id] = true
				t.Exclude = append(t.Exclude, id)
			}
		}
		if ov, ok := fields["overrides"]; ok {
			ovs, e := YAMLMap(ov)
			if e != nil {
				return c, e
			}
			for id, n := range ovs {
				if !targetID.MatchString(id) {
					return c, Fail("invalid_config", "override artifact id")
				}
				if _, e := YAMLMap(n, "project", "autoCreate"); e != nil {
					return c, e
				}
				t.Overrides[id] = n
			}
		}
		c.Targets[id] = t
	}
	return c, nil
}
