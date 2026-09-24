package delivery

import (
	"bytes"
	"gopkg.in/yaml.v3"
	"io"
	"path/filepath"
	"strings"
)

type Config struct {
	Directory    string
	SHA256       string
	Destinations map[string]Destination
	Deliveries   map[string]Binding
}
type Destination struct {
	Type    string
	Options yaml.Node
}
type Binding struct {
	Artifact    string
	Destination string
	Options     yaml.Node
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
func LoadConfig(path string) (Config, error) {
	var c Config
	b, e := ReadBounded(path, ConfigLimit)
	if e != nil {
		return c, e
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	var n yaml.Node
	if d.Decode(&n) != nil || len(n.Content) != 1 {
		return c, Fail("invalid_config", "YAML document")
	}
	var extra yaml.Node
	if d.Decode(&extra) != io.EOF {
		return c, Fail("invalid_config", "extra YAML document")
	}
	root, e := YAMLMap(*n.Content[0], "version", "destinations", "deliveries")
	if e != nil {
		return c, e
	}
	v := root["version"]
	if v.Tag != "!!int" || v.Value != "1" {
		return c, Fail("unsupported_version", "config.version")
	}
	ds, e := YAMLMap(root["destinations"])
	if e != nil {
		return c, e
	}
	bs, e := YAMLMap(root["deliveries"])
	if e != nil {
		return c, e
	}
	if len(ds) == 0 || len(bs) == 0 {
		return c, Fail("invalid_config", "empty destinations or deliveries")
	}
	c.Directory, e = filepath.Abs(filepath.Dir(path))
	if e != nil {
		return Config{}, Fail("invalid_config", "config directory")
	}
	c.SHA256 = Digest(b)
	c.Destinations = map[string]Destination{}
	c.Deliveries = map[string]Binding{}
	for name, n := range ds {
		m, e := YAMLMap(n, "type", "options")
		if e != nil {
			return Config{}, e
		}
		typ, e := YAMLString(m["type"], "destination.type")
		if e != nil {
			return Config{}, e
		}
		if _, e = YAMLMap(m["options"]); e != nil {
			return Config{}, e
		}
		c.Destinations[name] = Destination{typ, m["options"]}
	}
	for name, n := range bs {
		m, e := YAMLMap(n, "artifact", "destination", "options")
		if e != nil {
			return Config{}, e
		}
		a, e := YAMLString(m["artifact"], "delivery.artifact")
		if e != nil {
			return Config{}, e
		}
		dest, e := YAMLString(m["destination"], "delivery.destination")
		if e != nil {
			return Config{}, e
		}
		if _, ok := c.Destinations[dest]; !ok {
			return Config{}, Fail("invalid_config", "unknown destination reference")
		}
		if _, e = YAMLMap(m["options"]); e != nil {
			return Config{}, e
		}
		c.Deliveries[name] = Binding{a, dest, m["options"]}
	}
	return c, nil
}
