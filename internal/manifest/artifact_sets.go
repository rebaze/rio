package manifest

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/rebaze/rio/internal/buildcontext"
	"github.com/rebaze/rio/internal/enrichment"
	"github.com/rebaze/rio/internal/sbom"
	"gopkg.in/yaml.v3"
)

// ArtifactSet selects module marker files, then resolves an SBOM per module.
// Template settings are manifest-relative; only Template.SBOM is module-relative.
type ArtifactSet struct {
	Modules  string
	Exclude  []string
	IDFrom   string
	Template Artifact
}

type artifactSetSection struct {
	Modules    string                `yaml:"modules"`
	SBOM       string                `yaml:"sbom"`
	IDFrom     string                `yaml:"idFrom"`
	Exclude    []string              `yaml:"exclude"`
	Transforms []yaml.Node           `yaml:"transforms"`
	Enrichment *enrichment.Config    `yaml:"enrichment"`
	Context    *buildcontext.Binding `yaml:"context"`
}

// ValidateID applies the output identity rule without rewriting the name.
func ValidateID(id string) error {
	if !idPattern.MatchString(id) {
		return fmt.Errorf("%q does not match %s", id, idPattern)
	}
	return nil
}

func (l loader) artifactSets(f *fileSection, m *Manifest) error {
	for i, s := range f.ArtifactSets {
		field := fmt.Sprintf("artifactSets[%d]", i)
		for _, p := range []struct{ key, value string }{{"modules", s.Modules}, {"sbom", s.SBOM}} {
			if err := validateSetPattern(p.value); err != nil {
				return l.errf(field+"."+p.key, "%v", err)
			}
		}
		if s.IDFrom != "module-directory" {
			return l.errf(field+".idFrom", "must be module-directory, got %q", s.IDFrom)
		}
		for j, p := range s.Exclude {
			if err := validateSetPattern(p); err != nil {
				return l.errf(fmt.Sprintf("%s.exclude[%d]", field, j), "%v", err)
			}
		}
		a := Artifact{SBOM: s.SBOM, Context: s.Context}
		if err := buildcontext.ValidateBinding(s.Context); err != nil {
			return l.errf(field+".context", "%v", err)
		}
		resolved, err := enrichment.Resolve(f.Enrichment, s.Enrichment, field)
		if err != nil {
			return l.errf("", "%v", err)
		}
		if err := sbom.ValidateEnrichmentConfig(resolved); err != nil {
			return l.errf(field+".enrichment", "%v", err)
		}
		a.Enrichment = resolved
		for j := range s.Transforms {
			ts, err := l.transform(fmt.Sprintf("%s.transforms[%d]", field, j), &s.Transforms[j])
			if err != nil {
				return err
			}
			a.Transforms = append(a.Transforms, ts)
		}
		m.ArtifactSets = append(m.ArtifactSets, ArtifactSet{Modules: s.Modules, Exclude: s.Exclude, IDFrom: s.IDFrom, Template: a})
	}
	return nil
}

func validateSetPattern(pattern string) error {
	if strings.TrimSpace(pattern) == "" {
		return fmt.Errorf("must be a nonblank glob")
	}
	if strings.TrimSpace(pattern) != pattern {
		return fmt.Errorf("glob has leading or trailing whitespace")
	}
	// Treat Windows absolute/traversal spellings consistently even on Unix.
	portable := strings.ReplaceAll(pattern, `\`, "/")
	if filepath.IsAbs(pattern) || strings.HasPrefix(portable, "/") || (len(portable) > 1 && portable[1] == ':') {
		return fmt.Errorf("must be relative")
	}
	for _, segment := range strings.Split(portable, "/") {
		if segment == ".." {
			return fmt.Errorf("must not contain parent-traversal segments")
		}
	}
	if !doublestar.ValidatePattern(filepath.ToSlash(pattern)) {
		return fmt.Errorf("malformed glob %q", pattern)
	}
	return nil
}
