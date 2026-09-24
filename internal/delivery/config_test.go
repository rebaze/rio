package delivery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const configSeed = `version: 1
destinations:
  security:
    type: dependency-track
    options:
      url: https://example.test
deliveries:
  application-security:
    artifact: application
    destination: security
    options:
      project: {name: app, version: "1"}
`

func TestConfigStrict(t *testing.T) {
	for _, tc := range []struct {
		name, from, to string
		ok             bool
	}{
		{"valid", "", "", true}, {"version", "version: 1", "version: 2", false}, {"duplicate", "version: 1", "version: 1\nversion: 1", false}, {"null", "artifact: application", "artifact: null", false}, {"numeric", "artifact: application", "artifact: 1", false}, {"unknown", "artifact: application", "artifact: application\n    unknown: true", false}, {"reference", "destination: security", "destination: absent", false}, {"extra document", "", "\n---\nversion: 1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := configSeed
			if tc.from != "" {
				s = strings.Replace(s, tc.from, tc.to, 1)
			} else {
				s += tc.to
			}
			p := filepath.Join(t.TempDir(), "delivery.yaml")
			os.WriteFile(p, []byte(s), 0600)
			c, e := LoadConfig(p)
			if (e == nil) != tc.ok {
				t.Fatal(e)
			}
			if e == nil && (c.SHA256 != Digest([]byte(s)) || !filepath.IsAbs(c.Directory)) {
				t.Fatal("missing config identity")
			}
		})
	}
}
