package index_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/rebaze/rio/internal/index"
	"github.com/rebaze/rio/internal/sbom"
)

// fullIndex is the §4.2 example, extended with the two fields the index
// carries beyond it: transforms[].skipped (§6.2) and integrityFindings
// (§5 step 2b).
func fullIndex() *index.Index {
	return &index.Index{
		SchemaVersion: index.SchemaVersion,
		Tool:          index.Tool{Name: "rio", Version: "0.1.0"},
		Manifest: index.FileRef{
			Path:   "rio.yaml",
			SHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
		Artifacts: []index.Artifact{
			{
				ID: "rcp-client",
				Input: index.FileRef{
					Path:   "com.example.product.client/target/products/bom.json",
					SHA256: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
				},
				Output: index.FileRef{
					Path:   "rcp-client.cdx.json",
					SHA256: "cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90",
				},
				SpecVersion:     index.SpecVersions{Input: "1.5", Output: "1.6"},
				SchemaValidated: true,
				Components:      1284,
				Transforms: []index.TransformResult{
					{ID: "repair-purl/p2", Applied: 947, Unmapped: 12, Skipped: 31},
				},
				Gate:         index.GateOK,
				GateFindings: []index.GateFinding{},
			},
			{
				ID: "server-war",
				Input: index.FileRef{
					Path:   "com.example.server.web/target/bom.json",
					SHA256: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea",
				},
				Output: index.FileRef{
					Path:   "server-war.cdx.json",
					SHA256: "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6",
				},
				SpecVersion:     index.SpecVersions{Input: "1.6", Output: "1.6"},
				SchemaValidated: true,
				Components:      412,
				Transforms:      []index.TransformResult{},
				Gate:            index.GateFail,
				GateFindings: []index.GateFinding{
					{Subject: true, Missing: []string{"version"}},
					{Component: "pkg:maven/com.example/legacy-adapter", Missing: []string{"version"}},
				},
				IntegrityFindings: []sbom.IntegrityFinding{
					{Ref: "pkg:maven/com.example/ghost@1.0.0", Kind: "dependsOn", From: "pkg:maven/com.example/app@2.0.0"},
				},
			},
		},
	}
}

func TestMarshalGolden(t *testing.T) {
	got, err := index.Marshal(fullIndex())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := readGolden(t)
	if diff := cmp.Diff(want, string(got)); diff != "" {
		t.Errorf("index.json drifted from the §4.2 contract (-want +got):\n%s", diff)
	}
}

// TestEmptySlicesNeverNull guards the classic encoding/json bug: a nil slice
// serializes as null, and consumers of index.json iterate these arrays.
func TestEmptySlicesNeverNull(t *testing.T) {
	idx := &index.Index{
		SchemaVersion: index.SchemaVersion,
		Tool:          index.Tool{Name: "rio", Version: "0.1.0"},
		Manifest:      index.FileRef{Path: "rio.yaml", SHA256: "x"},
		Artifacts: []index.Artifact{{
			ID:   "only",
			Gate: index.GateFail,
			// Transforms, GateFindings, IntegrityFindings and the finding's
			// Missing are all left nil on purpose.
			GateFindings: []index.GateFinding{{Component: "pkg:maven/a/b"}},
		}},
	}

	data, err := index.Marshal(idx)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(data), "null") {
		t.Errorf("index.json contains null:\n%s", data)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	artifact := decoded["artifacts"].([]any)[0].(map[string]any)

	for _, key := range []string{"transforms", "gateFindings"} {
		v, ok := artifact[key]
		if !ok {
			t.Errorf("%q is missing; it must always be present", key)
			continue
		}
		if list, ok := v.([]any); !ok || list == nil {
			t.Errorf("%q = %#v, want an empty array", key, v)
		}
	}
	finding := artifact["gateFindings"].([]any)[0].(map[string]any)
	if list, ok := finding["missing"].([]any); !ok || list == nil {
		t.Errorf("gateFindings[0].missing = %#v, want an empty array", finding["missing"])
	}
	// integrityFindings is omitted when empty so a clean run produces exactly
	// the shape §4.2 documents.
	if _, ok := artifact["integrityFindings"]; ok {
		t.Errorf("integrityFindings must be omitted when empty, got %#v", artifact["integrityFindings"])
	}
}

func TestMarshalEmptyArtifactsIsArray(t *testing.T) {
	data, err := index.Marshal(&index.Index{
		SchemaVersion: index.SchemaVersion,
		Tool:          index.Tool{Name: "rio", Version: "0.1.0"},
		Manifest:      index.FileRef{Path: "rio.yaml", SHA256: "x"},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), `"artifacts": []`) {
		t.Errorf("empty artifacts must serialize as [], got:\n%s", data)
	}
}

// TestMarshalDeterministic backs §7: the same index marshals to the same bytes
// every time, because those bytes are hashed and referenced elsewhere.
func TestMarshalDeterministic(t *testing.T) {
	first, err := index.Marshal(fullIndex())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, err := index.Marshal(fullIndex())
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if string(first) != string(again) {
			t.Fatalf("run %d differs from run 0", i+1)
		}
	}
}

func TestMarshalDoesNotMutateInput(t *testing.T) {
	idx := &index.Index{
		Tool:      index.Tool{Name: "rio", Version: "0.1.0"},
		Manifest:  index.FileRef{Path: "rio.yaml", SHA256: "x"},
		Artifacts: []index.Artifact{{ID: "a", Gate: index.GateOK}},
	}
	if _, err := index.Marshal(idx); err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if idx.Artifacts[0].Transforms != nil {
		t.Errorf("Marshal filled in the caller's slice; it must normalize a copy")
	}
	if idx.SchemaVersion != 0 {
		t.Errorf("Marshal wrote schemaVersion back into the caller's index")
	}
}

func TestMarshalTrailingNewline(t *testing.T) {
	data, err := index.Marshal(fullIndex())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.HasSuffix(string(data), "}\n") {
		t.Errorf("index.json must end with a single trailing newline, got %q", tail(string(data)))
	}
	if strings.HasSuffix(string(data), "\n\n") {
		t.Errorf("index.json must not end with a blank line")
	}
}

// TestGateZeroValueRefused: gate is exactly "ok" or "fail" (§4.2). An artifact
// whose gate was never set must not silently serialize as "".
func TestGateZeroValueRefused(t *testing.T) {
	idx := fullIndex()
	idx.Artifacts[0].Gate = index.Gate("")

	if _, err := index.Marshal(idx); err == nil {
		t.Fatal("Marshal accepted an unset gate")
	} else if !strings.Contains(err.Error(), "rcp-client") {
		t.Errorf("error must name the artifact, got %v", err)
	}
}

func TestGateInvalidValueRefused(t *testing.T) {
	idx := fullIndex()
	idx.Artifacts[0].Gate = index.Gate("warn")

	_, err := index.Marshal(idx)
	if err == nil {
		t.Fatal("Marshal accepted gate \"warn\"")
	}
	if !strings.Contains(err.Error(), `"warn"`) {
		t.Errorf("error must quote the offending value, got %v", err)
	}
}

func TestGateRoundTrip(t *testing.T) {
	for _, want := range []index.Gate{index.GateOK, index.GateFail} {
		data, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshalling %q: %v", want, err)
		}
		var got index.Gate
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshalling %s: %v", data, err)
		}
		if got != want {
			t.Errorf("round trip: got %q, want %q", got, want)
		}
	}
	var g index.Gate
	if err := json.Unmarshal([]byte(`"warn"`), &g); err == nil {
		t.Error("decoding an unknown gate value must fail; rio record reads this file")
	}
}

// TestSchemaVersionDefaulted: schemaVersion is a constant of the format, not
// caller data, so a struct literal that omits it still writes the contract.
func TestSchemaVersionDefaulted(t *testing.T) {
	data, err := index.Marshal(&index.Index{
		Tool:     index.Tool{Name: "rio", Version: "0.1.0"},
		Manifest: index.FileRef{Path: "rio.yaml", SHA256: "x"},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), `"schemaVersion": 1`) {
		t.Errorf("want schemaVersion 1, got:\n%s", data)
	}
}

func TestNew(t *testing.T) {
	idx := index.New("0.1.0", index.FileRef{Path: "rio.yaml", SHA256: "x"})
	if idx.SchemaVersion != index.SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", idx.SchemaVersion, index.SchemaVersion)
	}
	if idx.Tool.Name != "rio" || idx.Tool.Version != "0.1.0" {
		t.Errorf("Tool = %+v", idx.Tool)
	}
	data, err := index.Marshal(idx)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), `"artifacts": []`) {
		t.Errorf("a fresh index must carry an empty artifacts array, got:\n%s", data)
	}
}

// TestNoTimestampField backs §7: nothing in the index may carry a run time,
// because the index bytes are hashed and a digest that changes between
// identical runs is worthless.
func TestNoTimestampField(t *testing.T) {
	data, err := index.Marshal(fullIndex())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	banned := map[string]bool{
		"generatedat": true, "timestamp": true, "createdat": true,
		"date": true, "time": true, "generated": true, "ranat": true,
	}
	var walk func(node any, path string)
	walk = func(node any, path string) {
		switch v := node.(type) {
		case map[string]any:
			for key, child := range v {
				if banned[strings.ToLower(key)] {
					t.Errorf("index.json must carry no timestamp, found %s.%s", path, key)
				}
				walk(child, path+"."+key)
			}
		case []any:
			for i, child := range v {
				walk(child, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	walk(doc, "")
}

// TestContractKeys pins the field names the upload script and rio record read
// (§4.2, §9c). It walks decoded JSON rather than the structs, so a changed tag
// fails here even if the golden were regenerated.
func TestContractKeys(t *testing.T) {
	data, err := index.Marshal(fullIndex())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	if got := doc["schemaVersion"]; got != float64(1) {
		t.Errorf("schemaVersion = %#v, want 1", got)
	}
	tool := doc["tool"].(map[string]any)
	if tool["name"] != "rio" || tool["version"] != "0.1.0" {
		t.Errorf("tool = %#v", tool)
	}
	manifest := doc["manifest"].(map[string]any)
	for _, key := range []string{"path", "sha256"} {
		if _, ok := manifest[key]; !ok {
			t.Errorf("manifest.%s missing", key)
		}
	}

	artifact := doc["artifacts"].([]any)[0].(map[string]any)
	for _, key := range []string{
		"id", "input", "output", "specVersion", "schemaValidated",
		"components", "transforms", "gate", "gateFindings",
	} {
		if _, ok := artifact[key]; !ok {
			t.Errorf("artifacts[0].%s missing", key)
		}
	}
	if got := artifact["gate"]; got != "ok" {
		t.Errorf("gate = %#v, want \"ok\"", got)
	}
	spec := artifact["specVersion"].(map[string]any)
	if spec["input"] != "1.5" || spec["output"] != "1.6" {
		t.Errorf("specVersion = %#v", spec)
	}
	tr := artifact["transforms"].([]any)[0].(map[string]any)
	for _, key := range []string{"id", "applied", "unmapped", "skipped"} {
		if _, ok := tr[key]; !ok {
			t.Errorf("transforms[0].%s missing", key)
		}
	}

	failed := doc["artifacts"].([]any)[1].(map[string]any)
	if got := failed["gate"]; got != "fail" {
		t.Errorf("gate = %#v, want \"fail\"", got)
	}
	integrity := failed["integrityFindings"].([]any)[0].(map[string]any)
	for _, key := range []string{"ref", "kind", "from"} {
		if _, ok := integrity[key]; !ok {
			t.Errorf("integrityFindings[0].%s missing", key)
		}
	}
}

// TestIntegrityFindingsKeyIsConditional pins the one deviation from "every
// array is an array": integrityFindings is present exactly when there is
// something to report, which is what the package doc promises consumers.
func TestIntegrityFindingsKeyIsConditional(t *testing.T) {
	idx := fullIndex()

	data, err := index.Marshal(idx)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	artifacts := doc["artifacts"].([]any)

	clean := artifacts[0].(map[string]any)
	if v, ok := clean["integrityFindings"]; ok {
		t.Errorf("a clean artifact must carry no integrityFindings key, got %#v", v)
	}
	dirty := artifacts[1].(map[string]any)
	list, ok := dirty["integrityFindings"].([]any)
	if !ok || len(list) != 1 {
		t.Errorf("integrityFindings = %#v, want a one element array", dirty["integrityFindings"])
	}
}

// TestValidateNamesThePosition: an artifact with no id has nothing else to be
// named by, so the error has to say which row it is.
func TestValidateNamesThePosition(t *testing.T) {
	idx := fullIndex()
	idx.Artifacts[1].ID = ""

	_, err := index.Marshal(idx)
	if err == nil {
		t.Fatal("Marshal accepted an artifact with no id")
	}
	if !strings.Contains(err.Error(), "artifacts[1]") {
		t.Errorf("error must name the position, got %v", err)
	}
}

// TestValidateRejectsDuplicateIDs: artifacts[].id is the handoff object's
// stable key (§4.2); two rows sharing one makes a lookup through it ambiguous.
func TestValidateRejectsDuplicateIDs(t *testing.T) {
	idx := fullIndex()
	idx.Artifacts[1].ID = idx.Artifacts[0].ID

	_, err := index.Marshal(idx)
	if err == nil {
		t.Fatal("Marshal accepted two artifacts with the same id")
	}
	for _, want := range []string{"artifacts[0]", "artifacts[1]", `"rcp-client"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must mention %s, got %v", want, err)
		}
	}
}

// TestNilIndexIsAnError: a nil index is a caller bug at the end of a run that
// may already have failed. Report it; do not add a panic to the pile.
func TestNilIndexIsAnError(t *testing.T) {
	var idx *index.Index

	if err := idx.Validate(); !errors.Is(err, index.ErrNilIndex) {
		t.Errorf("Validate(nil) = %v, want ErrNilIndex", err)
	}
	data, err := index.Marshal(nil)
	if !errors.Is(err, index.ErrNilIndex) {
		t.Errorf("Marshal(nil) = %v, want ErrNilIndex", err)
	}
	if data != nil {
		t.Errorf("Marshal(nil) returned %d bytes, want none", len(data))
	}
}

func tail(s string) string {
	if len(s) > 20 {
		return s[len(s)-20:]
	}
	return s
}

func readGolden(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "index.golden.json"))
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}
	return string(data)
}
