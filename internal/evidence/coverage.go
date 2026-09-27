package evidence

import "github.com/rebaze/rio/internal/delivery/batchrecord"

func exclusions(d batchrecord.Descriptor) []Exclusion {
	out := []Exclusion{}
	selected := func(filter []string, value string) bool {
		if len(filter) == 0 {
			return true
		}
		for _, v := range filter {
			if v == value {
				return true
			}
		}
		return false
	}
	as, otherAs, otherTs, allTs := []string{}, []string{}, []string{}, []string{}
	for _, a := range d.ArtifactIDs {
		if selected(d.Scope.ArtifactFilter, a) {
			as = append(as, a)
		} else {
			otherAs = append(otherAs, a)
		}
	}
	for _, t := range d.Scope.Targets {
		allTs = append(allTs, t.Name)
		if !selected(d.Scope.TargetFilter, t.Name) {
			otherTs = append(otherTs, t.Name)
		}
	}
	add := func(reason string, artifacts, targets []string) {
		if len(artifacts) > 0 && len(targets) > 0 {
			out = append(out, Exclusion{reason, artifacts, targets, int64(len(artifacts)) * int64(len(targets))})
		}
	}
	add("artifact-filter", otherAs, allTs)
	add("target-filter", as, otherTs)
	for _, t := range d.Scope.Targets {
		if !selected(d.Scope.TargetFilter, t.Name) {
			continue
		}
		excluded := []string{}
		lookup := map[string]bool{}
		for _, v := range t.Exclude {
			lookup[v] = true
		}
		for _, a := range as {
			if lookup[a] {
				excluded = append(excluded, a)
			}
		}
		add("target-configuration", excluded, []string{t.Name})
	}
	return out
}
