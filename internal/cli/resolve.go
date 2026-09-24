package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rebaze/rio/internal/discover"
	"github.com/rebaze/rio/internal/index"
	"github.com/rebaze/rio/internal/manifest"
)

// resolvedArtifact is the shared preflight result. Input is a concrete path,
// never a glob: interpreting it again would break filenames containing [, * etc.
type resolvedArtifact struct {
	Spec      manifest.Artifact
	Input     string
	Selection *index.Selection
	source    string
}

func resolveArtifacts(man *manifest.Manifest) ([]resolvedArtifact, error) {
	var result []resolvedArtifact
	ids := map[string]int{}
	var inputs []os.FileInfo
	type selectedRoot struct {
		info         os.FileInfo
		source, path string
	}
	var roots []selectedRoot
	add := func(spec manifest.Artifact, base, source string, selection *index.Selection) error {
		input, err := discover.Resolve(base, spec.ID, spec.SBOM)
		if err != nil {
			return usageErrorf("%s: %s: %v", man.Path, source, err)
		}
		if first, ok := ids[spec.ID]; ok {
			return usageErrorf("%s: ID %q collides: %s (%s) and %s (%s); exclude the module and declare an explicit artifact", man.Path, spec.ID, result[first].source, result[first].Input, source, input)
		}
		// Keep legacy explicit-only duplicate-input behavior. Once a generated
		// entry is involved, file identity catches symlinks and hard links alike.
		var info os.FileInfo
		if len(man.ArtifactSets) > 0 {
			info, err = os.Stat(input)
			if err != nil {
				return usageErrorf("%s: %s: %v", man.Path, source, err)
			}
			for i, other := range inputs {
				if (selection != nil || result[i].Selection != nil) && os.SameFile(info, other) {
					return usageErrorf("%s: %s (%s) and %s (%s) select the same physical SBOM", man.Path, result[i].source, result[i].Input, source, input)
				}
			}
		}
		ids[spec.ID] = len(result)
		inputs = append(inputs, info)
		result = append(result, resolvedArtifact{Spec: spec, Input: input, Selection: selection, source: source})
		return nil
	}
	for i, spec := range man.Artifacts {
		if err := add(spec, man.Dir, fmt.Sprintf("artifacts[%d]", i), nil); err != nil {
			return nil, err
		}
	}
	for i, set := range man.ArtifactSets {
		source := fmt.Sprintf("artifactSets[%d]", i)
		modules, err := discover.Modules(man.Dir, set.Modules, set.Exclude)
		if err != nil {
			return nil, usageErrorf("%s: %s: %v", man.Path, source, err)
		}
		for _, module := range modules {
			base := filepath.Join(man.Dir, filepath.FromSlash(module.Root))
			where := fmt.Sprintf("%s module %q (sbom %q)", source, module.Root, set.Template.SBOM)
			info, err := os.Stat(base)
			if err != nil {
				return nil, usageErrorf("%s: %s: %v", man.Path, where, err)
			}
			for _, r := range roots {
				if os.SameFile(info, r.info) {
					return nil, usageErrorf("%s: %s (%s) and %s (%s) select the same physical module", man.Path, r.source, r.path, source, module.Root)
				}
			}
			roots = append(roots, selectedRoot{info: info, source: source, path: module.Root})
			spec := set.Template
			spec.ID = filepath.Base(base)
			if err := manifest.ValidateID(spec.ID); err != nil {
				return nil, usageErrorf("%s: %s: generated ID %v; exclude the module and declare an explicit artifact", man.Path, where, err)
			}
			selection := &index.Selection{Version: 1, Kind: "artifactSet", Source: source, Module: module.Root, Marker: module.Marker}
			if err := add(spec, base, where, selection); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}
