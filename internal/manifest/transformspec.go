package manifest

import (
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rebaze/rio/internal/transform"
)

// transform parses one entry of artifacts[].transforms.
//
// The entry is a mapping with exactly one key naming the transform, its config
// as the value (§2). Zero keys is a typo and several keys make the declared
// order between them unreadable, so both are errors. The name itself is not
// checked here: internal/transform owns the set of known transforms (§9b).
func (l loader) transform(field string, node *yaml.Node) (TransformSpec, error) {
	if node.Kind != yaml.MappingNode {
		return TransformSpec{}, l.errf(field,
			"must be a mapping naming one transform, for example \"- repair-purl: {ecosystem: p2}\", got %s",
			describe(node))
	}
	// Content alternates key, value, so one transform is two entries.
	switch {
	case len(node.Content) == 0:
		return TransformSpec{}, l.errf(field, "names no transform, expected exactly one")
	case len(node.Content) > 2:
		return TransformSpec{}, l.errf(field,
			"names %d transforms (%s), expected exactly one per list entry so the order is unambiguous",
			len(node.Content)/2, strings.Join(mappingKeys(node), ", "))
	}

	key, value := node.Content[0], node.Content[1]
	if key.Kind != yaml.ScalarNode || key.Value == "" {
		return TransformSpec{}, l.errf(field, "the transform name must be a plain string")
	}

	cfg, err := l.transformConfig(field, key.Value, value)
	if err != nil {
		return TransformSpec{}, err
	}
	return TransformSpec{Name: key.Value, Config: cfg}, nil
}

// transformConfig decodes a transform's config node into a transform.Config,
// so internal/transform consumes manifest configuration without importing this
// package or knowing the values came from YAML.
//
// The decode target is a plain map[string]any rather than transform.Config
// itself, because yaml.v3 reuses the outer map's named type for every nested
// mapping: decoding straight into a Config would hand transform code nested
// values typed transform.Config, and a v, ok := x.(map[string]any) would fail
// on them. Below the top level no conversion is needed, as yaml.v3 yields
// map[string]any for mappings at every depth and rejects a non-string key
// rather than falling back to the map[any]any that v2 produced.
func (l loader) transformConfig(field, name string, value *yaml.Node) (transform.Config, error) {
	// An omitted config ("- repair-purl:") is an empty one, not an error: a
	// transform with no required options is configured by naming it.
	if value.Kind == 0 || value.Tag == "!!null" {
		return transform.Config{}, nil
	}
	if value.Kind != yaml.MappingNode {
		return nil, l.errf(field, "%s: config must be a mapping or empty, got %s", name, describe(value))
	}

	var raw map[string]any
	if err := value.Decode(&raw); err != nil {
		return nil, l.errf(field, "%s: %s", name, strings.TrimPrefix(err.Error(), "yaml: "))
	}
	cfg := make(transform.Config, len(raw))
	for k, v := range raw {
		cfg[k] = v
	}
	return cfg, nil
}

func mappingKeys(node *yaml.Node) []string {
	keys := make([]string, 0, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		keys = append(keys, node.Content[i].Value)
	}
	return keys
}
