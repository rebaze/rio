// Package purl is the manifest entry point for coordinate repair. It reads the
// ecosystem key and dispatches to the implementation for it.
//
//	transforms:
//	  - repair-purl:
//	      ecosystem: p2
//
// v1 ships one ecosystem. The dispatch exists so a second one arrives as a new
// sibling package rather than as a rewrite of this one.
package purl

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rebaze/rio/internal/transform"
	"github.com/rebaze/rio/internal/transform/purl/p2"
)

// ManifestKey is the name a manifest uses to select this transform.
const ManifestKey = "repair-purl"

// ecosystems maps the manifest's ecosystem value to its factory. Only used for
// lookup and for the error message, never iterated into the output.
var ecosystems = map[string]transform.Factory{
	"p2": p2.New,
}

func init() {
	transform.Register(ManifestKey, New)
}

// New dispatches on the ecosystem key. A missing ecosystem is a configuration
// error rather than a default: guessing which ecosystem a repository ships
// would silently rewrite coordinates the manifest never asked to be touched
// (§10).
func New(cfg transform.Config, baseDir string) (transform.Transform, error) {
	ecosystem, err := cfg.String("ecosystem", "")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ManifestKey, err)
	}
	if ecosystem == "" {
		return nil, fmt.Errorf("%s: %q is required, supported ecosystems are %s",
			ManifestKey, "ecosystem", supportedEcosystems())
	}
	factory, ok := ecosystems[ecosystem]
	if !ok {
		return nil, fmt.Errorf("%s: unsupported ecosystem %q, supported ecosystems are %s",
			ManifestKey, ecosystem, supportedEcosystems())
	}
	// The ecosystem owns the rest of the config, including which keys are
	// legal, because the option set differs per ecosystem.
	tr, err := factory(cfg, baseDir)
	if err != nil {
		return nil, fmt.Errorf("%s (ecosystem %s): %w", ManifestKey, ecosystem, err)
	}
	return tr, nil
}

// supportedEcosystems renders the known ecosystem values, sorted, so the error
// message does not depend on Go's map iteration order (§7).
func supportedEcosystems() string {
	names := make([]string, 0, len(ecosystems))
	for name := range ecosystems {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
