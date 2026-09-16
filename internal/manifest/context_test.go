package manifest_test

import (
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/manifest"
)

func TestArtifactContextBindingIsLoadedWithoutReadingContextFile(t *testing.T) {
	m, err := manifest.Load(write(t, `version: 1
artifacts:
  - id: app
    sbom: app.cdx.json
    context:
      file: absent-context.json
      require: [source.repository, build.url]
      replace: [source.repository]
`))
	if err != nil {
		t.Fatal(err)
	}
	context := m.Artifacts[0].Context
	if context == nil || context.File != "absent-context.json" || !sameContextStrings(context.Require, []string{"source.repository", "build.url"}) || !sameContextStrings(context.Replace, []string{"source.repository"}) {
		t.Fatalf("context = %+v", context)
	}
}

func TestArtifactContextRejectsStrictYAMLAndInvalidBindings(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"unknown key", "context: {file: ctx.json, required: [source.repository]}", "unknown key"},
		{"number file", "context: {file: 7}", "context.file"},
		{"scalar require", "context: {file: ctx.json, require: source.repository}", "context.require"},
		{"merged boolean", "<<: &defaults {context: {file: ctx.json, require: [true]}}", "context.require[0]"},
		{"duplicate selector", "context: {file: ctx.json, replace: [build.url, build.url]}", "listed more than once"},
		{"lifecycle replacement", "context: {file: ctx.json, replace: [lifecycle]}", "lifecycle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := manifest.Load(write(t, "version: 1\nartifacts:\n  - id: app\n    sbom: app.cdx.json\n    "+tc.body+"\n"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func sameContextStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
