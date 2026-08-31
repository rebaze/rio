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
	// The tag, not the kind: yaml resolves 5 and true to scalars too, and a
	// transform named "5" would be looked up in the registry and reported as
	// unknown, hiding the real mistake (§9b).
	if key.Tag != strTag || key.Value == "" {
		return TransformSpec{}, l.errf(field, "the transform name must be a plain string, got %s", describe(key))
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
// on them. Below the top level no conversion is needed, because stringKeys has
// already rejected every non-string key: with string keys only, yaml.v3 yields
// map[string]any for mappings at every depth.
func (l loader) transformConfig(field, name string, value *yaml.Node) (transform.Config, error) {
	// An omitted config ("- repair-purl:") is an empty one, not an error: a
	// transform with no required options is configured by naming it.
	if value.Kind == 0 || value.Tag == nullTag {
		return transform.Config{}, nil
	}
	if value.Kind != yaml.MappingNode {
		return nil, l.errf(field, "%s: config must be a mapping or empty, got %s", name, describe(value))
	}
	if err := l.stringKeys(field, name, value); err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := value.Decode(&raw); err != nil {
		// A duplicate config key is the one failure left once the keys are
		// known to be strings, and go-yaml says it plainly enough.
		return nil, l.errf(field, "%s: %s", name, yamlDetail(err))
	}
	cfg := make(transform.Config, len(raw))
	for k, v := range raw {
		cfg[k] = v
	}
	return cfg, nil
}

// stringKeys rejects a config key that is not a plain string, at any depth.
//
// yaml.v3 stringifies a non-string key only where the decode target is a
// map[string]any, which is the top level here; a nested mapping decodes into
// an interface and a float, int, bool or null key makes it a map[any]any.
// Transform code reading a nested config with v.(map[string]any) would fail on
// that, so the invariant is held here rather than left to each transform, and
// the author gets a message naming the key instead (§10).
func (l loader) stringKeys(field, name string, n *yaml.Node) error {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			// A merge key (<<) is yaml's own and merges an anchored
			// mapping; every mapping in the manifest is checked where it is
			// written, so the keys it merges in are strings too.
			if key := n.Content[i]; key.Tag != strTag && key.Tag != mergeTag {
				return l.errf(field, "%s: config keys must be plain strings, got %s on line %d",
					name, describe(key), key.Line)
			}
			if err := l.stringKeys(field, name, n.Content[i+1]); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if err := l.stringKeys(field, name, c); err != nil {
				return err
			}
		}
	}
	return nil
}

func mappingKeys(node *yaml.Node) []string {
	keys := make([]string, 0, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		keys = append(keys, node.Content[i].Value)
	}
	return keys
}
