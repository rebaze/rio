package delivery

import (
	"gopkg.in/yaml.v3"
	"strings"
	"testing"
)

func TestUnifiedConfig(t *testing.T) {
	for _, tc := range []struct {
		s  string
		ok bool
	}{
		{"targets: {security: {type: dependency-track, url: https://example.test}}", true},
		{"targets: {security: {type: null}}", false},
		{"targets: {security: {type: 1}}", false},
		{"targets: {security: {type: dependency-track, exclude: [app, app]}}", false},
		{"targets: {security: {type: dependency-track, overrides: {app: {apiKey: secret-canary}}}}", false},
		{"targets: {security: {type: dependency-track, url: secret-canary, url: other}}", false},
	} {
		var n yaml.Node
		yaml.Unmarshal([]byte(tc.s), &n)
		c, e := ParseConfig(*n.Content[0], "/manifest-dir", "digest")
		if (e == nil) != tc.ok {
			t.Fatal(tc.s, e)
		}
		if e != nil && strings.Contains(e.Error(), "secret-canary") {
			t.Fatal(e)
		}
		if e == nil && (c.Directory != "/manifest-dir" || c.SHA256 != "digest") {
			t.Fatal(c)
		}
	}
}
