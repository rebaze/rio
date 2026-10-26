package sbom

// ComponentObject is one component, or the subject, as raw JSON.
type ComponentObject struct {
	// Path is "metadata.component" for the subject, else the EveryComponent path.
	Path    string
	Subject bool
	// Object is nil for a non-object entry. Callers must not modify it.
	Object map[string]any
}

// ProfileComponents returns the subject first (when metadata.component is an
// object), then every component in EveryComponent order (same walk). Callers must not
// modify the returned maps.
func (d *Document) ProfileComponents() []ComponentObject {
	var out []ComponentObject
	if subj := d.metadataComponent(false); subj != nil {
		out = append(out, ComponentObject{Path: "metadata.component", Subject: true, Object: subj})
	}
	visitComponents(d.raw["components"], "components", func(path string, obj map[string]any) {
		out = append(out, ComponentObject{Path: path, Object: obj})
	})
	return out
}

// MetadataObject returns the metadata object, or nil when absent. Callers must
// not modify it.
func (d *Document) MetadataObject() map[string]any { return d.metadata(false) }

// HasVulnerabilities reports a non-empty vulnerabilities array.
func (d *Document) HasVulnerabilities() bool {
	v, _ := d.raw["vulnerabilities"].([]any)
	return len(v) > 0
}

// DependencyEntries returns each dependencies[].ref that is a string. Callers
// must not modify the map.
func (d *Document) DependencyEntries() map[string]bool {
	out := map[string]bool{}
	list, _ := d.raw["dependencies"].([]any)
	for _, e := range list {
		if o, ok := e.(map[string]any); ok {
			if ref, ok := o["ref"].(string); ok {
				out[ref] = true
			}
		}
	}
	return out
}

// CompositionCoverage returns refs named in assemblies or dependencies of any
// composition whose aggregate is a string other than not_specified. Callers
// must not modify the map.
func (d *Document) CompositionCoverage() map[string]bool {
	out := map[string]bool{}
	list, _ := d.raw["compositions"].([]any)
	for _, e := range list {
		o, ok := e.(map[string]any)
		if !ok {
			continue
		}
		agg, ok := o["aggregate"].(string)
		if !ok || agg == "not_specified" {
			continue
		}
		for _, key := range []string{"assemblies", "dependencies"} {
			refs, _ := o[key].([]any)
			for _, r := range refs {
				if s, ok := r.(string); ok {
					out[s] = true
				}
			}
		}
	}
	return out
}

// AtLeast reports whether CycloneDX spec version spec is at least floor.
func AtLeast(spec, floor string) bool { return compareSpecVersions(spec, floor) >= 0 }
