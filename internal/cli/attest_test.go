package cli

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// Exercise multiple artifacts with different transforms, gate outcomes and
// integrity findings so a statement cannot accidentally claim another row.
func TestAttestPreservesEachArtifactRecord(t *testing.T) {
	// Add the second artifact before the output section.
	manifest := strings.Replace(tychoManifest, "output:\n",
		"  - id: server-war\n    sbom: in/gate-missing-version.cdx.json\noutput:\n", 1)
	for _, tc := range []struct {
		mode string
		exit int
	}{{"warn", ExitOK}, {"fail", ExitGate}} {
		t.Run(tc.mode, func(t *testing.T) {
			dir := project(t, manifest, "tycho-rcp.cdx.json", "gate-missing-version.cdx.json")
			requireExit(t, rio(t, dir, "normalize", "--attest", "--gate", tc.mode), tc.exit)
			idx := decode(t, readFile(t, dir, "target", "rio", "index.json"))
			for _, row := range idx["artifacts"].([]any) {
				a := row.(map[string]any)
				id := a["id"].(string)
				s := decode(t, readFile(t, dir, "target", "rio", id+".intoto.json"))
				if s["_type"] != "https://in-toto.io/Statement/v1" || s["predicateType"] != "https://rebaze.com/attestation/sbom-normalization/v1" {
					t.Fatalf("invalid statement types: %v", s)
				}
				wantPredicate := map[string]any{"tool": idx["tool"], "manifest": idx["manifest"], "artifact": a}
				if diff := cmp.Diff(wantPredicate, s["predicate"]); diff != "" {
					t.Fatalf("%s predicate lost index fields (-want +got):\n%s", id, diff)
				}
				output := a["output"].(map[string]any)
				name := output["path"].(string)
				sum := fmt.Sprintf("%x", sha256.Sum256(readFile(t, dir, "target", "rio", name)))
				if output["sha256"] != sum {
					t.Fatalf("index digest does not match %s", name)
				}
				wantSubject := []any{map[string]any{"name": name, "digest": map[string]any{"sha256": sum}}}
				if diff := cmp.Diff(wantSubject, s["subject"]); diff != "" {
					t.Fatalf("%s subject does not match written SBOM (-want +got):\n%s", id, diff)
				}
			}
		})
	}
}

func TestAttestIsOptInAndDeterministic(t *testing.T) {
	dir := project(t, tychoManifest, "tycho-rcp.cdx.json")
	requireExit(t, rio(t, dir, "normalize"), ExitOK)
	if _, err := os.Stat(filepath.Join(dir, "target", "rio", "rcp-client.intoto.json")); !os.IsNotExist(err) {
		t.Fatalf("without --attest, statement stat = %v, want absent", err)
	}
	before := map[string]string{}
	for _, name := range []string{"rcp-client.cdx.json", "index.json"} {
		before[name] = string(readFile(t, dir, "target", "rio", name))
	}
	requireExit(t, rio(t, dir, "normalize", "--attest"), ExitOK)
	for name, want := range before {
		if got := string(readFile(t, dir, "target", "rio", name)); got != want {
			t.Fatalf("--attest changed %s", name)
		}
	}
	first := string(readFile(t, dir, "target", "rio", "rcp-client.intoto.json"))
	// A different output directory must not change the claim's bytes.
	requireExit(t, rio(t, dir, "normalize", "--attest", "--out", "other"), ExitOK)
	if got := string(readFile(t, dir, "other", "rcp-client.intoto.json")); got != first {
		t.Fatal("statement differs between identical runs in different output directories")
	}
}

func TestAttestInputErrorWritesNothing(t *testing.T) {
	manifest := "version: 1\nartifacts:\n" +
		"  - id: good\n    sbom: in/plain-maven.cdx.json\n" +
		"  - id: bad\n    sbom: in/missing.json\n"
	dir := project(t, manifest, "plain-maven.cdx.json")
	r := rio(t, dir, "normalize", "--attest")
	requireExit(t, r, ExitUsage)
	requireStderr(t, r, "bad")
	requireNothingWritten(t, dir)
}

func TestAttestWriteFailureDoesNotPublishIndex(t *testing.T) {
	dir := project(t, tychoManifest, "tycho-rcp.cdx.json")
	// A directory where the statement belongs forces its atomic rename to fail.
	if err := os.MkdirAll(filepath.Join(dir, "target", "rio", "rcp-client.intoto.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := rio(t, dir, "normalize", "--attest")
	requireExit(t, r, ExitInternal)
	requireStderr(t, r, "rcp-client", "intoto.json")
	if _, err := os.Stat(filepath.Join(dir, "target", "rio", "index.json")); !os.IsNotExist(err) {
		t.Fatalf("failed statement write published index: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "target", "rio"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("failed statement write left temp files: %v", entries)
	}
}
