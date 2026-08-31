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

// EcosystemKey is the manifest key that selects the implementation, and the
// first key `rio plan` reports for this transform.
const EcosystemKey = "ecosystem"

// ecosystems maps the manifest's ecosystem value to its implementation. Only
// used for lookup and for the error message, never iterated into the output.
//
// A factory and a describer are held together so the two dispatches cannot
// disagree about which ecosystems exist: an ecosystem `rio normalize` builds
// and `rio plan` does not know about would describe a run that cannot happen,
// and the reverse would describe one that does not exist.
var ecosystems = map[string]struct {
	new      transform.Factory
	describe func(transform.Config) (p2.Scope, error)
}{
	"p2": {new: p2.New, describe: p2.Describe},
}

func init() {
	transform.Register(ManifestKey, New, Describe)
}

// New dispatches on the ecosystem key.
func New(cfg transform.Config, baseDir string) (transform.Transform, error) {
	ecosystem, err := ecosystemOf(cfg)
	if err != nil {
		return nil, err
	}
	impl, ok := ecosystems[ecosystem]
	if !ok {
		return nil, fmt.Errorf("%s: unsupported ecosystem %q, supported ecosystems are %s",
			ManifestKey, ecosystem, supportedEcosystems())
	}
	// The ecosystem owns the rest of the config, including which keys are
	// legal, because the option set differs per ecosystem.
	tr, err := impl.new(cfg, baseDir)
	if err != nil {
		return nil, fmt.Errorf("%s (ecosystem %s): %w", ManifestKey, ecosystem, err)
	}
	return tr, nil
}

// Describe reports what a repair-purl transform resolves to, for `rio plan`,
// dispatching on the same key and rejecting the same configurations as New.
//
// The ecosystem leads the option list because it is what selects everything
// after it; the rest are the ecosystem's own, in the ecosystem's own order.
func Describe(cfg transform.Config) ([]transform.Option, error) {
	ecosystem, err := ecosystemOf(cfg)
	if err != nil {
		return nil, err
	}
	impl, ok := ecosystems[ecosystem]
	if !ok {
		return nil, fmt.Errorf("%s: unsupported ecosystem %q, supported ecosystems are %s",
			ManifestKey, ecosystem, supportedEcosystems())
	}
	scope, err := impl.describe(cfg)
	if err != nil {
		return nil, fmt.Errorf("%s (ecosystem %s): %w", ManifestKey, ecosystem, err)
	}
	return append([]transform.Option{{Key: EcosystemKey, Value: ecosystem}}, scope.Options()...), nil
}

// ecosystemOf reads and requires the dispatch key. A missing ecosystem is a
// configuration error rather than a default: guessing which ecosystem a
// repository ships would silently rewrite coordinates the manifest never asked
// to be touched (§10).
func ecosystemOf(cfg transform.Config) (string, error) {
	value, err := cfg.String(EcosystemKey, "")
	if err != nil {
		return "", fmt.Errorf("%s: %w", ManifestKey, err)
	}
	if value == "" {
		return "", fmt.Errorf("%s: %q is required, supported ecosystems are %s",
			ManifestKey, EcosystemKey, supportedEcosystems())
	}
	return value, nil
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
