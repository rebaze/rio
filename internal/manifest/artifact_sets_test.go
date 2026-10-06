package manifest_test

import (
	"fmt"
	"github.com/rebaze/rio/internal/manifest"
	"strings"
	"testing"
)

func TestArtifactSetsDeclarations(t *testing.T) {
	for _, explicit := range []string{"", "artifacts: [{id: desktop, sbom: desktop.json}]\n"} {
		_, err := manifest.Load(write(t, "version: 1\n"+explicit+`enrichment: {producer: {name: Example}}
artifactSets:
  - modules: services/**/*server/pom.xml
    sbom: target/bom.json
    idFrom: module-directory
    exclude: [services/experimental-server/pom.xml]
    enrichment: {subject: {group: example}}
    context: {file: absent.json}
    transforms: [{repair-purl: {ecosystem: p2, table: absent.json}}]
`))
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestArtifactSetsValidation(t *testing.T) {
	for i, tc := range []struct{ body, want string }{
		{`artifactSets: [{sbom: target/bom.json, idFrom: module-directory}]`, "modules"},
		{`artifactSets: [{modules: ' ', sbom: target/bom.json, idFrom: module-directory}]`, "modules"},
		{`artifactSets: [{modules: 7, sbom: target/bom.json, idFrom: module-directory}]`, "modules"},
		{`artifactSets: [{modules: '**/pom.xml', sbom: true, idFrom: module-directory}]`, "sbom"},
		{`artifactSets: [{modules: '**/pom.xml', sbom: bom.json, idFrom: name}]`, "idFrom"},
		{`artifactSets: [{modules: '**/pom.xml', sbom: bom.json, idFrom: module-directory, subject: {name: x}}]`, "unknown key"},
		{`artifactSets: [{modules: '/pom.xml', sbom: bom.json, idFrom: module-directory}]`, "relative"},
		{`artifactSets: [{modules: '../pom.xml', sbom: bom.json, idFrom: module-directory}]`, "parent"},
		{`artifactSets: [{modules: '**/pom.xml', sbom: 'target/../bom.json', idFrom: module-directory}]`, "parent"},
		{`artifactSets: [{modules: '**/pom.xml', sbom: bom.json, idFrom: module-directory, exclude: ['[']}]`, "exclude[0]"},
		{`artifactSets: [{modules: '**/pom.xml', sbom: bom.json, idFrom: module-directory, exclude: [true]}]`, "exclude[0]"},
		{`artifactSets: [{modules: '**/pom.xml', sbom: bom.json, idFrom: module-directory, exclude: foo}]`, "exclude"},
		{`artifactSets: [{modules: '**/pom.xml', sbom: bom.json, idFrom: module-directory, context: {file: 7}}]`, "context.file"},
		{`artifactSets: [{modules: '**/pom.xml', sbom: bom.json, idFrom: module-directory, enrichment: {producer: {name: true}}}]`, "producer.name"},
		{`artifactSets: null`, "artifactSets"},
		{`artifactSets: {modules: pom.xml}`, "artifactSets"},
		{`artifactSets: [null]`, "artifactSets[0]"},
		{`artifactSets: [{modules: pom.xml, modules: other.xml}]`, "already defined"},
		{"artifactSets: []\n---\nversion: 1", "more than one"},
	} {
		t.Run(fmt.Sprintf("case-%02d", i), func(t *testing.T) {
			_, err := manifest.Load(write(t, "version: 1\nartifacts: [{id: old, sbom: old.json}]\n"+tc.body+"\n"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestArtifactSetsAliasesAndMerges(t *testing.T) {
	m, err := manifest.Load(write(t, `version: 1
artifactSets:
  - &base
    modules: &selector 'services/*/pom.xml'
    sbom: target/bom.json
    idFrom: module-directory
    enrichment: {producer: {name: Example}}
  - <<: *base
    modules: *selector
    exclude: ['services/excluded/pom.xml']
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.ArtifactSets) != 2 || m.ArtifactSets[1].Modules != "services/*/pom.xml" || m.ArtifactSets[1].Template.Enrichment.Fields[0].Source != "artifactSets[1].enrichment.producer.name" {
		t.Fatalf("merged sets: %+v", m.ArtifactSets)
	}
	for i, body := range []string{
		`artifactSets:
  - transforms: [{custom: {value: &number 7}}]
    modules: *number
    sbom: bom.json
    idFrom: module-directory
`,
		`artifactSets:
  - &base {modules: 'services/*/pom.xml', sbom: bom.json, idFrom: module-directory}
  - <<: *base
    exclude: ['[']
`,
	} {
		t.Run(fmt.Sprintf("invalid-%d", i), func(t *testing.T) {
			_, err := manifest.Load(write(t, "version: 1\n"+body))
			want := []string{"artifactSets[0].modules", "artifactSets[1].exclude[0]"}[i]
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v, want %s", err, want)
			}
		})
	}
}
