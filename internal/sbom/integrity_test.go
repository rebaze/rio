package sbom_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/rebaze/rio/internal/sbom"
)

// cyclonedx-maven-plugin 2.7.9 emits a dependencies[].ref for a component it
// never wrote, on a plain Tycho build. Report it, never repair it, never fail
// on it (§5 step 2b).
func TestIntegrityFindingsOnTheRealFixture(t *testing.T) {
	doc := load(t, fixture(t, "tycho-rcp.cdx.json"))

	want := []sbom.IntegrityFinding{{
		Ref:  "pkg:p2/org.eclipse.equinox.executable_root.gtk.linux.x86_64@3.8.2300.v20231106-1826?classifier=binary&location=https%3A%2F%2Fdownload.eclipse.org%2Freleases%2F2023-12%2F",
		Kind: "dependency",
	}}
	if diff := cmp.Diff(want, doc.IntegrityFindings()); diff != "" {
		t.Fatalf("IntegrityFindings() (-want +got):\n%s", diff)
	}
}

func TestIntegrityFindingsCleanDocument(t *testing.T) {
	doc := load(t, fixture(t, "plain-maven.cdx.json"))
	if got := doc.IntegrityFindings(); len(got) != 0 {
		t.Fatalf("IntegrityFindings() = %v, want none", got)
	}
}

func TestIntegrityFindingsDanglingDependsOn(t *testing.T) {
	doc := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
"components":[{"bom-ref":"a","type":"library","name":"a","version":"1"}],
"dependencies":[{"ref":"a","dependsOn":["a","ghost"]}]}`))

	want := []sbom.IntegrityFinding{{Ref: "ghost", Kind: "dependsOn", From: "a"}}
	if diff := cmp.Diff(want, doc.IntegrityFindings()); diff != "" {
		t.Fatalf("IntegrityFindings() (-want +got):\n%s", diff)
	}
}

// A ref may legitimately point at metadata.component, a nested component or a
// service. None of those is dangling.
func TestIntegrityFindingsResolveAgainstEveryBOMRefHolder(t *testing.T) {
	doc := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
"metadata":{"component":{"bom-ref":"root","type":"application","name":"r","version":"1"}},
"components":[{"bom-ref":"outer","type":"library","name":"o","version":"1",
  "components":[{"bom-ref":"nested","type":"library","name":"n","version":"1"}]}],
"services":[{"bom-ref":"svc","name":"s"}],
"dependencies":[{"ref":"root","dependsOn":["outer","nested","svc"]}]}`))

	if got := doc.IntegrityFindings(); len(got) != 0 {
		t.Fatalf("IntegrityFindings() = %v, want none", got)
	}
}

func TestIntegrityFindingsAreDeduplicatedAndOrdered(t *testing.T) {
	doc := load(t, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
"components":[{"bom-ref":"a","type":"library","name":"a","version":"1"}],
"dependencies":[
  {"ref":"a","dependsOn":["zeta","alpha","alpha"]},
  {"ref":"missing","dependsOn":["alpha"]}]}`))

	want := []sbom.IntegrityFinding{
		{Ref: "alpha", Kind: "dependsOn", From: "a"},
		{Ref: "alpha", Kind: "dependsOn", From: "missing"},
		{Ref: "missing", Kind: "dependency"},
		{Ref: "zeta", Kind: "dependsOn", From: "a"},
	}
	if diff := cmp.Diff(want, doc.IntegrityFindings()); diff != "" {
		t.Fatalf("IntegrityFindings() (-want +got):\n%s", diff)
	}
}
