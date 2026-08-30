package cli

import (
	"encoding/json"

	"github.com/google/go-cmp/cmp"

	"github.com/rebaze/rio/internal/gate"
	"github.com/rebaze/rio/internal/manifest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Exit 2 aborts the whole run before any file is written (§1, §5, §10). The
// message must name the manifest path and the offending field.
func TestExitTwoConditionsWriteNothing(t *testing.T) {
	cases := []struct {
		name     string
		manifest string
		fixtures []string
		args     []string
		wants    []string
	}{
		{
			name:     "missing manifest",
			manifest: "", // written, then deleted below
			args:     []string{"normalize", "--manifest", "absent.yaml"},
			wants:    []string{"absent.yaml"},
		},
		{
			name:     "version is not 1",
			manifest: "version: 2\nartifacts:\n  - id: a\n    sbom: \"in/plain-maven.cdx.json\"\n",
			fixtures: []string{"plain-maven.cdx.json"},
			wants:    []string{"version"},
		},
		{
			name:     "no artifacts",
			manifest: "version: 1\nartifacts: []\n",
			wants:    []string{"artifacts"},
		},
		{
			name:     "duplicate artifact id",
			manifest: "version: 1\nartifacts:\n  - id: a\n    sbom: \"in/plain-maven.cdx.json\"\n  - id: a\n    sbom: \"in/plain-maven.cdx.json\"\n",
			fixtures: []string{"plain-maven.cdx.json"},
			wants:    []string{"a"},
		},
		{
			name:     "id fails the pattern",
			manifest: "version: 1\nartifacts:\n  - id: Not Valid\n    sbom: \"in/plain-maven.cdx.json\"\n",
			fixtures: []string{"plain-maven.cdx.json"},
			wants:    []string{"id"},
		},
		{
			name:     "unknown manifest key",
			manifest: "version: 1\nartifacts:\n  - id: a\n    sbom: \"in/plain-maven.cdx.json\"\noutputs:\n  specVersionFloor: \"1.6\"\n",
			fixtures: []string{"plain-maven.cdx.json"},
			wants:    []string{"outputs"},
		},
		{
			name:     "unsupported spec version floor",
			manifest: "version: 1\nartifacts:\n  - id: a\n    sbom: \"in/plain-maven.cdx.json\"\noutput:\n  specVersionFloor: \"1.4\"\n",
			fixtures: []string{"plain-maven.cdx.json"},
			wants:    []string{"specVersionFloor"},
		},
		{
			name:     "glob matches zero files",
			manifest: "version: 1\nartifacts:\n  - id: rcp-client\n    sbom: \"in/**/nothing.json\"\n",
			fixtures: []string{"plain-maven.cdx.json"},
			// §10: name the artifact id, the pattern as resolved, and the
			// absolute directory searched.
			wants: []string{"rcp-client", "in/**/nothing.json"},
		},
		{
			name:     "glob matches several files",
			manifest: "version: 1\nartifacts:\n  - id: a\n    sbom: \"in/*.cdx.json\"\n",
			fixtures: []string{"plain-maven.cdx.json", "uplift-1.4.cdx.json"},
			wants:    []string{"plain-maven.cdx.json", "uplift-1.4.cdx.json"},
		},
		{
			name:     "unknown transform",
			manifest: "version: 1\nartifacts:\n  - id: a\n    sbom: \"in/plain-maven.cdx.json\"\n    transforms:\n      - repair-everything: {}\n",
			fixtures: []string{"plain-maven.cdx.json"},
			wants:    []string{"repair-everything", "repair-purl"},
		},
		{
			name:     "unknown transform ecosystem",
			manifest: "version: 1\nartifacts:\n  - id: a\n    sbom: \"in/plain-maven.cdx.json\"\n    transforms:\n      - repair-purl:\n          ecosystem: npm\n",
			fixtures: []string{"plain-maven.cdx.json"},
			wants:    []string{"npm"},
		},
		{
			name:     "input is not CycloneDX",
			manifest: "version: 1\nartifacts:\n  - id: a\n    sbom: \"in/notcyclonedx.json\"\n",
			wants:    []string{"CycloneDX"},
		},
		{
			name:     "input is schema-invalid at its own version",
			manifest: "version: 1\nartifacts:\n  - id: a\n    sbom: \"in/invalid-1.6.cdx.json\"\n",
			fixtures: []string{"invalid-1.6.cdx.json"},
			wants:    []string{"before rio touched it"},
		},
		{
			name:     "gate mode is neither warn nor fail",
			manifest: "version: 1\nartifacts:\n  - id: a\n    sbom: \"in/plain-maven.cdx.json\"\n",
			fixtures: []string{"plain-maven.cdx.json"},
			args:     []string{"normalize", "--gate", "explode"},
			wants:    []string{"explode", "warn", "fail"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := project(t, tc.manifest, tc.fixtures...)
			if tc.name == "missing manifest" {
				if err := os.Remove(filepath.Join(dir, "rio.yaml")); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name == "input is not CycloneDX" {
				if err := os.WriteFile(filepath.Join(dir, "in", "notcyclonedx.json"),
					[]byte(`{"spdxVersion":"SPDX-2.3"}`), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			args := tc.args
			if args == nil {
				args = []string{"normalize"}
			}
			r := rio(t, dir, args...)

			requireExit(t, r, ExitUsage)
			requireStderr(t, r, tc.wants...)
			requireNothingWritten(t, dir)
		})
	}
}

// A second artifact's configuration error must abort before the first
// artifact's output is written. Otherwise exit 2 leaves half a run on disk.
func TestExitTwoOnALaterArtifactStillWritesNothing(t *testing.T) {
	manifest := "version: 1\nartifacts:\n" +
		"  - id: good\n    sbom: \"in/plain-maven.cdx.json\"\n" +
		"  - id: bad\n    sbom: \"in/nothing-matches-this.json\"\n"
	dir := project(t, manifest, "plain-maven.cdx.json")

	r := rio(t, dir, "normalize")
	requireExit(t, r, ExitUsage)
	requireStderr(t, r, "bad")
	requireNothingWritten(t, dir)
}

// Exit 1 still writes every output file and the index: a human has to be able
// to see why the gate failed (§1).
func TestGateFailWritesEverythingAndExitsOne(t *testing.T) {
	manifest := "version: 1\nartifacts:\n  - id: server-war\n    sbom: \"in/gate-missing-version.cdx.json\"\n"
	dir := project(t, manifest, "gate-missing-version.cdx.json")

	r := rio(t, dir, "normalize", "--gate", "fail")
	requireExit(t, r, ExitGate)
	requireStderr(t, r, "server-war", "missing version")

	if !strings.Contains(r.stdout, "gate FAIL") {
		t.Fatalf("stdout does not report the failure:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "1 artifact, 1 gate failure") {
		t.Fatalf("summary line is wrong:\n%s", r.stdout)
	}

	readFile(t, dir, "target", "rio", "server-war.cdx.json")
	entry := indexArtifact(t, dir, "target/rio", 0)
	if entry["gate"] != "fail" {
		t.Fatalf("index gate = %v, want fail", entry["gate"])
	}
	findings, _ := entry["gateFindings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("gateFindings = %v, want one", findings)
	}
	finding, _ := findings[0].(map[string]any)
	if finding["component"] != "pkg:maven/com.tkse/legacy-adapter" {
		t.Fatalf("gateFindings[0].component = %v", finding["component"])
	}
	missing, _ := finding["missing"].([]any)
	if len(missing) != 1 || missing[0] != "version" {
		t.Fatalf("gateFindings[0].missing = %v, want [version]", missing)
	}
}

// Under warn the result is still recorded as fail in the index and printed to
// stderr, but the exit code is unaffected. Teams ratchet thresholds up over
// weeks, and a tool that breaks every build on day one gets removed on day two
// (§5 step 4).
func TestGateWarnRecordsTheFailureWithoutFailingTheRun(t *testing.T) {
	manifest := "version: 1\nartifacts:\n  - id: server-war\n    sbom: \"in/gate-missing-version.cdx.json\"\n"
	dir := project(t, manifest, "gate-missing-version.cdx.json")

	r := rio(t, dir, "normalize") // warn is the default
	requireExit(t, r, ExitOK)
	requireStderr(t, r, "failed the gate")

	if entry := indexArtifact(t, dir, "target/rio", 0); entry["gate"] != "fail" {
		t.Fatalf("index gate = %v, want fail even under --gate warn", entry["gate"])
	}
}

// A component whose purl is still pkg:p2/... after the transform passes the
// gate. It is a valid purl; unmapped is a count in the index, not a failure
// (§5 step 4).
func TestUnmappedComponentsDoNotFailTheGate(t *testing.T) {
	dir := project(t, tychoManifest, "tycho-rcp.cdx.json")

	r := rio(t, dir, "normalize", "--gate", "fail")
	requireExit(t, r, ExitOK)

	entry := indexArtifact(t, dir, "target/rio", 0)
	if entry["gate"] != "ok" {
		t.Fatalf("gate = %v, want ok despite an unmapped component", entry["gate"])
	}
	transforms, _ := entry["transforms"].([]any)
	stat, _ := transforms[0].(map[string]any)
	if stat["unmapped"].(json.Number).String() != "1" {
		t.Fatalf("unmapped = %v, want 1", stat["unmapped"])
	}
}

// A subject failure fails the artifact regardless of gate.require, because the
// DependencyTrack project version comes from it and an artifact with no
// identity of its own cannot be recorded against (§4.3d).
func TestSubjectFailureFailsRegardlessOfGateRequire(t *testing.T) {
	dir := project(t, "version: 1\nartifacts:\n  - id: a\n    sbom: \"in/nosubject.cdx.json\"\ngate:\n  require: []\n")
	if err := os.WriteFile(filepath.Join(dir, "in", "nosubject.cdx.json"), []byte(
		`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
"components":[{"type":"library","name":"x","version":"1","bom-ref":"x"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	r := rio(t, dir, "normalize", "--gate", "fail")
	requireExit(t, r, ExitGate)
	requireStderr(t, r, "subject")

	finding, _ := indexArtifact(t, dir, "target/rio", 0)["gateFindings"].([]any)
	entry, _ := finding[0].(map[string]any)
	if entry["subject"] != true {
		t.Fatalf("gateFindings[0] = %v, want subject: true", entry)
	}
}

// The subject override sets metadata.component and records what it replaced,
// which is the normal case for a Tycho aggregator (§4.3d).
func TestSubjectOverride(t *testing.T) {
	manifest := "version: 1\nartifacts:\n  - id: rcp-client\n    sbom: \"in/tycho-rcp.cdx.json\"\n" +
		"    subject:\n      name: TKSE RCP Client\n      version: \"2026.1.0\"\n"
	dir := project(t, manifest, "tycho-rcp.cdx.json")
	requireExit(t, rio(t, dir, "normalize", "--gate", "fail"), ExitOK)

	out := decode(t, readFile(t, dir, "target", "rio", "rcp-client.cdx.json"))
	meta, _ := out["metadata"].(map[string]any)
	component, _ := meta["component"].(map[string]any)
	if component["name"] != "TKSE RCP Client" || component["version"] != "2026.1.0" {
		t.Fatalf("metadata.component = %v", component)
	}
	// The purl and bom-ref of metadata.component are not part of the override.
	if component["bom-ref"] != "pkg:maven/tycho-demo/example@1.0.0-SNAPSHOT?type=eclipse-repository" {
		t.Fatalf("the subject override touched bom-ref: %v", component["bom-ref"])
	}

	got := properties(t, out)["rebaze:normalize:subject-override"]
	if len(got) != 1 || !strings.Contains(got[0], "from=example@1.0.0-SNAPSHOT") ||
		!strings.Contains(got[0], "to=TKSE RCP Client@2026.1.0") {
		t.Fatalf("subject-override = %v", got)
	}
}

func TestTwoArtifactsAreIndependent(t *testing.T) {
	manifest := "version: 1\nartifacts:\n" +
		"  - id: rcp-client\n    sbom: \"in/tycho-rcp.cdx.json\"\n" +
		"    transforms:\n      - repair-purl:\n          ecosystem: p2\n" +
		"  - id: server-war\n    sbom: \"in/gate-missing-version.cdx.json\"\n"
	dir := project(t, manifest, "tycho-rcp.cdx.json", "gate-missing-version.cdx.json")

	// A gate failure in one artifact does not stop the others (§5).
	r := rio(t, dir, "normalize", "--gate", "fail")
	requireExit(t, r, ExitGate)

	readFile(t, dir, "target", "rio", "rcp-client.cdx.json")
	readFile(t, dir, "target", "rio", "server-war.cdx.json")

	if got := indexArtifact(t, dir, "target/rio", 0)["gate"]; got != "ok" {
		t.Fatalf("rcp-client gate = %v, want ok", got)
	}
	if got := indexArtifact(t, dir, "target/rio", 1)["gate"]; got != "fail" {
		t.Fatalf("server-war gate = %v, want fail", got)
	}
	// Columns line up so a Jenkins log stays readable (§1).
	if !strings.Contains(r.stdout, "2 artifacts, 1 gate failure") {
		t.Fatalf("summary line is wrong:\n%s", r.stdout)
	}
}

func TestQuietSuppressesPerArtifactLinesButKeepsTheSummary(t *testing.T) {
	dir := project(t, tychoManifest, "tycho-rcp.cdx.json")

	r := rio(t, dir, "normalize", "--quiet")
	requireExit(t, r, ExitOK)

	if strings.Contains(r.stdout, "components") {
		t.Fatalf("--quiet still printed a per artifact line:\n%s", r.stdout)
	}
	if got, want := r.stdout, "1 artifact, no gate failures\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestOutFlagChoosesTheDirectory(t *testing.T) {
	dir := project(t, tychoManifest, "tycho-rcp.cdx.json")
	requireExit(t, rio(t, dir, "normalize", "--out", "build/sboms"), ExitOK)

	readFile(t, dir, "build", "sboms", "rcp-client.cdx.json")
	readFile(t, dir, "build", "sboms", "index.json")
}

// Files rio did not write are left alone (§4.1).
func TestExistingFilesInTheOutputDirectoryAreLeftAlone(t *testing.T) {
	dir := project(t, tychoManifest, "tycho-rcp.cdx.json")
	outDir := filepath.Join(dir, "target", "rio")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(outDir, "someone-elses.json")
	if err := os.WriteFile(keep, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	requireExit(t, rio(t, dir, "normalize"), ExitOK)
	if got := string(readFile(t, keep)); got != "{}" {
		t.Fatalf("an unrelated file was rewritten: %q", got)
	}
}

func TestVersionCommandAndFlag(t *testing.T) {
	dir := project(t, tychoManifest)
	want := "rio 0.1.0-test (commit: 0000000, built: 1970-01-01T00:00:00Z)\n"

	if r := rio(t, dir, "version"); r.exit != ExitOK || r.stdout != want {
		t.Fatalf("rio version = %d %q, want 0 %q", r.exit, r.stdout, want)
	}
	if r := rio(t, dir, "--version"); r.exit != ExitOK || r.stdout != want {
		t.Fatalf("rio --version = %d %q, want 0 %q", r.exit, r.stdout, want)
	}
}

func TestUnknownFlagAndCommandAreUsageErrors(t *testing.T) {
	dir := project(t, tychoManifest)

	if r := rio(t, dir, "normalize", "--nonsense"); r.exit != ExitUsage {
		t.Fatalf("unknown flag exit = %d, want %d", r.exit, ExitUsage)
	}
	if r := rio(t, dir, "teleport"); r.exit != ExitUsage {
		t.Fatalf("unknown command exit = %d, want %d", r.exit, ExitUsage)
	}
	if r := rio(t, dir, "normalize", "extra-argument"); r.exit != ExitUsage {
		t.Fatalf("unexpected argument exit = %d, want %d", r.exit, ExitUsage)
	}
}

// No absolute paths in output; recorded paths are relative to the manifest
// directory (§7). The index's digests are a contract, and a machine-local
// path in it makes two identical runs produce different bytes.
func TestManifestPathInTheIndexIsNeverAbsolute(t *testing.T) {
	dir := project(t, tychoManifest, "tycho-rcp.cdx.json")
	abs := filepath.Join(dir, "rio.yaml")

	// The same run, reached three different ways, must produce the same index.
	var digests []string
	for _, args := range [][]string{
		{"normalize"},
		{"normalize", "--manifest", "rio.yaml"},
		{"normalize", "--manifest", abs},
	} {
		requireExit(t, rio(t, dir, args...), ExitOK)

		idx := decode(t, readFile(t, dir, "target", "rio", "index.json"))
		manifest, _ := idx["manifest"].(map[string]any)
		path, _ := manifest["path"].(string)
		if path != "rio.yaml" {
			t.Fatalf("%v recorded manifest.path = %q, want %q", args, path, "rio.yaml")
		}
		digests = append(digests, string(readFile(t, dir, "target", "rio", "index.json")))
	}
	for i := range digests[1:] {
		if digests[i+1] != digests[0] {
			t.Fatal("index.json differs depending on how the manifest was named")
		}
	}
}

// The three gate requirements are defined twice, as manifest strings and as
// gate.Requirement values, and converted at the call site. Adding a fourth to
// one side without the other would make the gate silently stop checking it.
func TestGateRequirementsAgreeWithTheManifest(t *testing.T) {
	var fromManifest []gate.Requirement
	for _, r := range manifest.DefaultRequire() {
		fromManifest = append(fromManifest, gate.Requirement(r))
	}
	if diff := cmp.Diff(gate.All(), fromManifest); diff != "" {
		t.Fatalf("manifest.DefaultRequire() and gate.All() have drifted (-gate +manifest):\n%s", diff)
	}
}
