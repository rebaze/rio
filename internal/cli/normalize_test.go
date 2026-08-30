package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/rebaze/rio/internal/index"
)

const tychoManifest = `version: 1
artifacts:
  - id: rcp-client
    sbom: "in/tycho-rcp.cdx.json"
    transforms:
      - repair-purl:
          ecosystem: p2
output:
  specVersionFloor: "1.6"
gate:
  require: [name, version, purl]
`

// The acceptance run: a real cyclonedx-maven-plugin 2.7.9 Tycho document in,
// a valid 1.6 document out, every repair traceable from the output alone.
func TestNormalizeTychoFixture(t *testing.T) {
	dir := project(t, tychoManifest, "tycho-rcp.cdx.json")
	r := rio(t, dir, "normalize")
	requireExit(t, r, ExitOK)

	golden(t, "rcp-client.cdx.json", readFile(t, dir, "target", "rio", "rcp-client.cdx.json"))
	golden(t, "index.json", readFile(t, dir, "target", "rio", "index.json"))

	if want := "rcp-client  12 components   repaired 8    unmapped 1    gate ok\n" +
		"1 artifact, no gate failures\n"; r.stdout != want {
		t.Fatalf("stdout =\n%q\nwant\n%q", r.stdout, want)
	}
}

// §11 fixture 1 spells out what this one document has to exercise. Each
// assertion below names its clause.
func TestNormalizeTychoFixtureCoversEveryClauseOfFixtureOne(t *testing.T) {
	dir := project(t, tychoManifest, "tycho-rcp.cdx.json")
	requireExit(t, rio(t, dir, "normalize"), ExitOK)

	in := decode(t, readFile(t, dir, "in", "tycho-rcp.cdx.json"))
	out := decode(t, readFile(t, dir, "target", "rio", "rcp-client.cdx.json"))
	got := purls(t, out)

	cases := []struct {
		clause string
		index  int
		want   string
	}{
		{"four segment Eclipse qualifier versions become three", 2,
			"pkg:maven/org.eclipse.platform/org.eclipse.core.databinding@1.13.100"},
		{"a bundle present in the seeded table is mapped", 7,
			"pkg:maven/org.eclipse.platform/org.eclipse.osgi@3.18.600"},
		{"a bundle absent from the table keeps its p2 purl, version fixed", 9,
			"pkg:p2/org.eclipse.equinox.launcher.gtk.linux.x86_64@1.2.800?classifier=osgi.bundle&location=https%3A%2F%2Fdownload.eclipse.org%2Freleases%2F2023-12%2F"},
		{"a first-party reactor module is skipped, not mapped and not touched", 0,
			"pkg:p2/example.plugin@1.0.0.today?classifier=osgi.bundle&location=https%3A%2F%2Fwww.example.p2.repo%2F"},
		{"a non-numeric qualifier on a first-party snapshot is left alone", 1,
			"pkg:p2/example.feature@1.0.0.today?classifier=org.eclipse.update.feature&location=https%3A%2F%2Fwww.example.p2.repo%2F"},
		{"an Eclipse feature is skipped on classifier", 10,
			"pkg:p2/org.eclipse.equinox.executable@3.8.2300.v20231106-1826?classifier=org.eclipse.update.feature&location=https%3A%2F%2Fdownload.eclipse.org%2Freleases%2F2023-12%2F"},
		{"a component already carrying a pkg:maven purl is not touched", 11,
			"pkg:maven/p2.p2.installable.unit/org.eclipse.equinox.executable_root.gtk.linux.x86_64@3.8.2300.v20231106-1826?type=p2-installable-unit"},
	}
	for _, tc := range cases {
		t.Run(tc.clause, func(t *testing.T) {
			if got[tc.index] != tc.want {
				t.Fatalf("components[%d].purl =\n  %s\nwant\n  %s", tc.index, got[tc.index], tc.want)
			}
		})
	}

	t.Run("bom-ref values survive untouched, so the graph survives", func(t *testing.T) {
		if diff := cmp.Diff(bomRefs(t, in), bomRefs(t, out)); diff != "" {
			t.Fatalf("bom-refs changed (-input +output):\n%s", diff)
		}
		if diff := cmp.Diff(in["dependencies"], out["dependencies"]); diff != "" {
			t.Fatalf("the dependency graph changed (-input +output):\n%s", diff)
		}
	})

	t.Run("the dangling dependency ref is reported and not repaired", func(t *testing.T) {
		artifacts := indexOf(t, run{dir: dir}, filepath.Join("target", "rio"))["artifacts"].([]any)
		findings, _ := artifacts[0].(map[string]any)["integrityFindings"].([]any)
		if len(findings) != 1 {
			t.Fatalf("integrityFindings = %v, want exactly one", findings)
		}
		ref, _ := findings[0].(map[string]any)["ref"].(string)
		if !strings.Contains(ref, "executable_root.gtk.linux.x86_64") || !strings.Contains(ref, "classifier=binary") {
			t.Fatalf("integrityFindings[0].ref = %q", ref)
		}
	})
}

// Every repair must be traceable from the output document alone, without the
// index and without the input (cross-cutting acceptance).
func TestRepairsAreTraceableFromTheOutputAlone(t *testing.T) {
	dir := project(t, tychoManifest, "tycho-rcp.cdx.json")
	requireExit(t, rio(t, dir, "normalize"), ExitOK)

	out := decode(t, readFile(t, dir, "target", "rio", "rcp-client.cdx.json"))
	props := properties(t, out)

	if got := len(props["rebaze:normalize:repair"]); got != 8 {
		t.Fatalf("repair records = %d, want 8", got)
	}
	if got := len(props["rebaze:normalize:unmapped"]); got != 1 {
		t.Fatalf("unmapped records = %d, want 1", got)
	}
	for _, record := range props["rebaze:normalize:repair"] {
		for _, field := range []string{"rule=repair-purl/p2", "| from=pkg:p2/", "| to="} {
			if !strings.Contains(record, field) {
				t.Fatalf("repair record %q is missing %q", record, field)
			}
		}
	}
	if got := props["rebaze:normalize:unmapped"][0]; !strings.Contains(got, "reason=no mapping entry") {
		t.Fatalf("unmapped record %q does not carry a reason", got)
	}

	// Skipped components are counted in the index but deliberately not written
	// into the document: on a product SBOM most components are out of scope
	// and the noise would bury the hits.
	if _, found := props["rebaze:normalize:skipped"]; found {
		t.Fatal("skipped components were written into metadata.properties")
	}

	for _, name := range []string{"tool", "artifact-id", "manifest-sha256", "input-sha256", "spec-uplift"} {
		if len(props["rebaze:normalize:"+name]) != 1 {
			t.Fatalf("missing run metadata property rebaze:normalize:%s", name)
		}
	}
	if got, want := props["rebaze:normalize:spec-uplift"][0], "from=1.4 to=1.6"; got != want {
		t.Fatalf("spec-uplift = %q, want %q", got, want)
	}
	if got, want := props["rebaze:normalize:tool"][0], "rio 0.1.0-test"; got != want {
		t.Fatalf("tool = %q, want %q", got, want)
	}
}

// Same inputs, same manifest, same binary version produce byte identical
// outputs. Output digests are referenced from index.json, and a digest that
// changes between identical runs is worthless (§7).
func TestTwoRunsAreByteIdentical(t *testing.T) {
	dir := project(t, tychoManifest, "tycho-rcp.cdx.json")

	requireExit(t, rio(t, dir, "normalize"), ExitOK)
	firstDoc := readFile(t, dir, "target", "rio", "rcp-client.cdx.json")
	firstIndex := readFile(t, dir, "target", "rio", "index.json")

	requireExit(t, rio(t, dir, "normalize"), ExitOK)
	if diff := cmp.Diff(string(firstDoc), string(readFile(t, dir, "target", "rio", "rcp-client.cdx.json"))); diff != "" {
		t.Fatalf("the output document differs between runs (-first +second):\n%s", diff)
	}
	if diff := cmp.Diff(string(firstIndex), string(readFile(t, dir, "target", "rio", "index.json"))); diff != "" {
		t.Fatalf("index.json differs between runs (-first +second):\n%s", diff)
	}
}

// Component membership never changes in v1: the array in equals the array out,
// member for member (§4.3, cross-cutting acceptance).
func TestComponentMembershipNeverChanges(t *testing.T) {
	fixtures := []string{
		"tycho-rcp.cdx.json", "plain-maven.cdx.json", "gate-missing-version.cdx.json",
		"uplift-1.4.cdx.json", "evidence-1.5-object.cdx.json", "future-1.9.cdx.json",
		"unmodelled-fields.cdx.json",
	}
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			manifest := "version: 1\nartifacts:\n  - id: a\n    sbom: \"in/" + name + "\"\n" +
				"    transforms:\n      - repair-purl:\n          ecosystem: p2\n"
			dir := project(t, manifest, name)
			requireExit(t, rio(t, dir, "normalize", "--gate", "warn"), ExitOK)

			in := decode(t, readFile(t, dir, "in", name))
			out := decode(t, readFile(t, dir, "target", "rio", "a.cdx.json"))

			inList, _ := in["components"].([]any)
			outList, _ := out["components"].([]any)
			if len(inList) != len(outList) {
				t.Fatalf("component count changed: %d in, %d out", len(inList), len(outList))
			}
			// Order and identity: bom-ref, name and version are all untouched,
			// so the sequence must match exactly (§6.4).
			if diff := cmp.Diff(bomRefs(t, in), bomRefs(t, out)); diff != "" {
				t.Fatalf("component order or identity changed (-input +output):\n%s", diff)
			}
		})
	}
}

// §11 fixture 2: no p2 content and no transforms, so the output is the input
// plus only the records rio always writes.
func TestPlainDocumentGainsOnlyTheRunMetadata(t *testing.T) {
	manifest := "version: 1\nartifacts:\n  - id: server-war\n    sbom: \"in/plain-maven.cdx.json\"\n"
	dir := project(t, manifest, "plain-maven.cdx.json")
	requireExit(t, rio(t, dir, "normalize"), ExitOK)

	in := decode(t, readFile(t, dir, "in", "plain-maven.cdx.json"))
	out := decode(t, readFile(t, dir, "target", "rio", "server-war.cdx.json"))

	if diff := cmp.Diff(in["components"], out["components"]); diff != "" {
		t.Fatalf("components changed with no transform configured (-input +output):\n%s", diff)
	}
	if diff := cmp.Diff(in["dependencies"], out["dependencies"]); diff != "" {
		t.Fatalf("dependencies changed (-input +output):\n%s", diff)
	}

	props := properties(t, out)
	for name := range props {
		if strings.HasPrefix(name, "rebaze:normalize:") {
			switch name {
			case "rebaze:normalize:tool", "rebaze:normalize:artifact-id",
				"rebaze:normalize:manifest-sha256", "rebaze:normalize:input-sha256":
			default:
				t.Errorf("unexpected property on a document that needed no work: %s", name)
			}
		}
	}
	// Already at the floor, so nothing to record.
	if _, found := props["rebaze:normalize:spec-uplift"]; found {
		t.Error("spec-uplift was recorded on a document already at the floor")
	}
	if got := props["maven.goal"]; len(got) != 1 || got[0] != "makeBom" {
		t.Errorf("the generator's own property was lost or moved: %v", got)
	}
}

// §11 fixture 4: 1.4 in, 1.6 out, the uplift recorded, and the deprecated flat
// metadata.tools array left flat (§4.3c).
func TestUpliftFromOneFourRecordsItselfAndLeavesToolsFlat(t *testing.T) {
	manifest := "version: 1\nartifacts:\n  - id: client\n    sbom: \"in/uplift-1.4.cdx.json\"\n"
	dir := project(t, manifest, "uplift-1.4.cdx.json")
	requireExit(t, rio(t, dir, "normalize"), ExitOK)

	out := decode(t, readFile(t, dir, "target", "rio", "client.cdx.json"))
	if got := out["specVersion"]; got != "1.6" {
		t.Fatalf("specVersion = %v, want 1.6", got)
	}
	if got := properties(t, out)["rebaze:normalize:spec-uplift"]; len(got) != 1 || got[0] != "from=1.4 to=1.6" {
		t.Fatalf("spec-uplift = %v", got)
	}

	meta, _ := out["metadata"].(map[string]any)
	tools, ok := meta["tools"].([]any)
	if !ok {
		t.Fatalf("metadata.tools = %T, want the flat array form preserved", meta["tools"])
	}
	if len(tools) != 2 {
		t.Fatalf("len(metadata.tools) = %d, want the generator's entry plus rio", len(tools))
	}

	entry := indexArtifact(t, dir, "target/rio", 0)
	spec, _ := entry["specVersion"].(map[string]any)
	if spec["input"] != "1.4" || spec["output"] != "1.6" {
		t.Fatalf("index specVersion = %v", spec)
	}
	if entry["schemaValidated"] != true {
		t.Fatalf("schemaValidated = %v, want true", entry["schemaValidated"])
	}
}

// §11 fixture 5: evidence.identity is an object at 1.5 and an array at 1.6.
func TestIdentityEvidenceObjectIsWrappedWithItsContentIntact(t *testing.T) {
	manifest := "version: 1\nartifacts:\n  - id: scanner\n    sbom: \"in/evidence-1.5-object.cdx.json\"\n"
	dir := project(t, manifest, "evidence-1.5-object.cdx.json")
	requireExit(t, rio(t, dir, "normalize"), ExitOK)

	out := decode(t, readFile(t, dir, "target", "rio", "scanner.cdx.json"))
	components, _ := out["components"].([]any)
	component, _ := components[0].(map[string]any)
	evidence, _ := component["evidence"].(map[string]any)

	identity, ok := evidence["identity"].([]any)
	if !ok {
		t.Fatalf("evidence.identity = %T, want an array after uplift", evidence["identity"])
	}
	if len(identity) != 1 {
		t.Fatalf("len(evidence.identity) = %d, want the generator's single entry", len(identity))
	}
	entry, _ := identity[0].(map[string]any)
	if entry["confidence"] != json.Number("0.8") {
		t.Fatalf("confidence = %v, want the input's 0.8 preserved", entry["confidence"])
	}
	methods, _ := entry["methods"].([]any)
	method, _ := methods[0].(map[string]any)
	if method["technique"] != "filename" || method["value"] != "slf4j-api-2.0.9.jar" {
		t.Fatalf("the wrapped entry lost content: %v", method)
	}
}

// §11 fixture 6: a spec version above the highest embedded schema passes
// through, validation is skipped, and the index says so (§3).
func TestFutureSpecVersionPassesThroughUnvalidated(t *testing.T) {
	manifest := "version: 1\nartifacts:\n  - id: future\n    sbom: \"in/future-1.9.cdx.json\"\n"
	dir := project(t, manifest, "future-1.9.cdx.json")
	requireExit(t, rio(t, dir, "normalize"), ExitOK)

	out := decode(t, readFile(t, dir, "target", "rio", "future.cdx.json"))
	if got := out["specVersion"]; got != "1.9" {
		t.Fatalf("specVersion = %v, want 1.9 passed through", got)
	}
	// A field invented after 1.6, which no pinned library models, survives
	// because every write lands on the raw tree (§8).
	if got := out["postQuantumReadiness"]; got == nil {
		t.Fatal("a top-level key no library models was dropped")
	}

	entry := indexArtifact(t, dir, "target/rio", 0)
	if entry["schemaValidated"] != false {
		t.Fatalf("schemaValidated = %v, want false", entry["schemaValidated"])
	}
	spec, _ := entry["specVersion"].(map[string]any)
	if spec["input"] != "1.9" || spec["output"] != "1.9" {
		t.Fatalf("index specVersion = %v, want 1.9 in and out", spec)
	}
}

// §11 fixture 8: every field in the input survives to the output, including
// constructs a round trip through the typed model would rewrite.
func TestFieldsTheTypedModelWouldRewriteSurviveExactly(t *testing.T) {
	manifest := "version: 1\nartifacts:\n  - id: round-trip\n    sbom: \"in/unmodelled-fields.cdx.json\"\n"
	dir := project(t, manifest, "unmodelled-fields.cdx.json")
	requireExit(t, rio(t, dir, "normalize"), ExitOK)

	in := decode(t, readFile(t, dir, "in", "unmodelled-fields.cdx.json"))
	out := decode(t, readFile(t, dir, "target", "rio", "round-trip.cdx.json"))

	// cyclonedx-go injects resolves[].description on encode. rio must not.
	if diff := cmp.Diff(in["components"], out["components"]); diff != "" {
		t.Fatalf("components changed (-input +output):\n%s", diff)
	}
	if diff := cmp.Diff(in["services"], out["services"]); diff != "" {
		t.Fatalf("services changed (-input +output):\n%s", diff)
	}
}

// §11 fixture 7: invalid at its own declared spec version. The message has to
// distinguish "your SBOM was already broken" from "rio broke your SBOM",
// because the first will be the common case and it is a finding, not a bug
// report (§5 step 2b).
func TestInvalidInputIsAttributedToTheInput(t *testing.T) {
	manifest := "version: 1\nartifacts:\n  - id: broken\n    sbom: \"in/invalid-1.6.cdx.json\"\n"
	dir := project(t, manifest, "invalid-1.6.cdx.json")
	r := rio(t, dir, "normalize")

	requireExit(t, r, ExitUsage)
	requireStderr(t, r,
		"is not valid CycloneDX 1.6 as generated, before rio touched it",
		"This is a finding about the input, not a rio bug",
		"/components/0/type",
	)
	if strings.Contains(r.stderr, "bug in rio") {
		t.Fatalf("an invalid input was attributed to rio:\n%s", r.stderr)
	}
	requireNothingWritten(t, dir)
}

func indexArtifact(t *testing.T, dir, out string, i int) map[string]any {
	t.Helper()

	idx := decode(t, readFile(t, dir, filepath.FromSlash(out), "index.json"))
	artifacts, _ := idx["artifacts"].([]any)
	if i >= len(artifacts) {
		t.Fatalf("index has %d artifacts, wanted index %d", len(artifacts), i)
	}
	entry, _ := artifacts[i].(map[string]any)
	return entry
}

func requireNothingWritten(t *testing.T, dir string) {
	t.Helper()

	// Exit 2 writes nothing (§1). The output directory must not even exist.
	if _, err := os.Stat(filepath.Join(dir, "target")); !os.IsNotExist(err) {
		entries, _ := os.ReadDir(filepath.Join(dir, "target", "rio"))
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("the output directory exists after an exit 2, holding %v", names)
	}
}

// index.json's digests describe the bytes a consumer will read, so they are
// computed after writing, over the file on disk (§4.2).
func TestIndexDigestsMatchTheBytesOnDisk(t *testing.T) {
	dir := project(t, tychoManifest, "tycho-rcp.cdx.json")
	requireExit(t, rio(t, dir, "normalize"), ExitOK)

	outDir := filepath.Join(dir, "target", "rio")
	entry := indexArtifact(t, dir, "target/rio", 0)

	output, _ := entry["output"].(map[string]any)
	path, _ := output["path"].(string)
	if filepath.IsAbs(path) || strings.Contains(path, string(filepath.Separator)) {
		t.Fatalf("output.path = %q, want it relative to the index file's own directory", path)
	}
	want, err := index.SHA256File(filepath.Join(outDir, path))
	if err != nil {
		t.Fatal(err)
	}
	if output["sha256"] != want {
		t.Fatalf("output.sha256 = %v, want %v", output["sha256"], want)
	}

	in, _ := entry["input"].(map[string]any)
	inPath, _ := in["path"].(string)
	if filepath.IsAbs(inPath) {
		t.Fatalf("input.path = %q, want it relative to the manifest directory (§7)", inPath)
	}
	wantIn, err := index.SHA256File(filepath.Join(dir, filepath.FromSlash(inPath)))
	if err != nil {
		t.Fatal(err)
	}
	if in["sha256"] != wantIn {
		t.Fatalf("input.sha256 = %v, want %v", in["sha256"], wantIn)
	}
}

// No timestamps anywhere in the output body or the index, and
// metadata.timestamp is preserved exactly as found (§7).
func TestNoTimestampsAreAddedAndTheGeneratorsIsPreserved(t *testing.T) {
	dir := project(t, tychoManifest, "tycho-rcp.cdx.json")
	requireExit(t, rio(t, dir, "normalize"), ExitOK)

	in := decode(t, readFile(t, dir, "in", "tycho-rcp.cdx.json"))
	out := decode(t, readFile(t, dir, "target", "rio", "rcp-client.cdx.json"))
	inMeta, _ := in["metadata"].(map[string]any)
	outMeta, _ := out["metadata"].(map[string]any)
	if inMeta["timestamp"] != outMeta["timestamp"] {
		t.Fatalf("metadata.timestamp = %v, want the input's %v", outMeta["timestamp"], inMeta["timestamp"])
	}

	idx := readFile(t, dir, "target", "rio", "index.json")
	for _, forbidden := range []string{"timestamp", "generatedAt", "generated", "createdAt"} {
		if strings.Contains(string(idx), forbidden) {
			t.Fatalf("index.json contains %q; the index carries no run timestamp (§7)", forbidden)
		}
	}
}
