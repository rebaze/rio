package index_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/index"
)

func TestRelPath(t *testing.T) {
	tests := []struct {
		name   string
		base   string
		target string
		want   string
	}{
		{"nested", "/repo", "/repo/target/rio/rcp-client.cdx.json", "target/rio/rcp-client.cdx.json"},
		{"same directory", "/repo/target/rio", "/repo/target/rio/index.json", "index.json"},
		{"base with trailing slash", "/repo/", "/repo/rio.yaml", "rio.yaml"},
		{"unclean segments", "/repo/./sub/..", "/repo/rio.yaml", "rio.yaml"},
		{"both relative", "target/rio", "target/rio/server-war.cdx.json", "server-war.cdx.json"},
		{"sibling directory", "/repo/target/rio", "/repo/rio.yaml", "../../rio.yaml"},
		{"different root", "/repo", "/elsewhere/bom.json", "../elsewhere/bom.json"},
		{"parent", "/repo/sub", "/repo", ".."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := index.RelPath(tt.base, tt.target)
			if err != nil {
				t.Fatalf("RelPath(%q, %q): %v", tt.base, tt.target, err)
			}
			if got != tt.want {
				t.Errorf("RelPath(%q, %q) = %q, want %q", tt.base, tt.target, got, tt.want)
			}
		})
	}
}

// TestRelPathUpwardEscapeSurvivesIntoTheIndex: a manifest whose sbom glob
// points at a sibling module -- "../ext/bom.json", an ordinary multi-module
// layout -- must be recorded, not refused. §7 bars absolute paths; a path
// relative to the manifest directory is exactly what it asks for, whichever
// way it points.
func TestRelPathUpwardEscapeSurvivesIntoTheIndex(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "repo")
	target := filepath.Join(root, "ext", "bom.json")

	got, err := index.RelPath(base, target)
	if err != nil {
		t.Fatalf("RelPath(%q, %q): %v", base, target, err)
	}
	if want := "../ext/bom.json"; got != want {
		t.Fatalf("RelPath = %q, want %q", got, want)
	}
	if filepath.IsAbs(got) {
		t.Errorf("RelPath returned an absolute path: %q", got)
	}
	if strings.Contains(got, root) {
		t.Errorf("RelPath leaked the build machine's layout: %q", got)
	}

	// Round trip it through the index: the recorded path is what a consumer
	// reads back, so assert there and not just at the function boundary.
	idx := &index.Index{
		Tool:     index.Tool{Name: "rio", Version: "0.1.0"},
		Manifest: index.FileRef{Path: "rio.yaml", SHA256: "x"},
		Artifacts: []index.Artifact{{
			ID:    "outside",
			Input: index.FileRef{Path: got, SHA256: "x"},
			Gate:  index.GateOK,
		}},
	}
	data, err := index.Marshal(idx)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var doc struct {
		Artifacts []struct {
			Input struct {
				Path string `json:"path"`
			} `json:"input"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if want := "../ext/bom.json"; doc.Artifacts[0].Input.Path != want {
		t.Errorf("index recorded input.path = %q, want %q", doc.Artifacts[0].Input.Path, want)
	}
}

func TestRelPathRefusesBaseItself(t *testing.T) {
	if got, err := index.RelPath("/repo/target/rio", "/repo/target/rio"); err == nil {
		t.Fatalf("RelPath of the base itself = %q, want an error", got)
	}
}

func TestRelPathRefusesEmpty(t *testing.T) {
	if _, err := index.RelPath("/repo", ""); err == nil {
		t.Error("an empty target must be refused")
	}
	if _, err := index.RelPath("", "/repo/rio.yaml"); err == nil {
		t.Error("an empty base must be refused")
	}
}

// TestRelPathIsSlashSeparated: index.json must read the same whatever platform
// wrote it (§7).
func TestRelPathNeverAbsoluteAndAlwaysSlashed(t *testing.T) {
	base := filepath.Join(string(filepath.Separator), "repo", "a")
	target := filepath.Join(base, "b", "c", "bom.json")

	got, err := index.RelPath(base, target)
	if err != nil {
		t.Fatalf("RelPath: %v", err)
	}
	if filepath.IsAbs(got) || strings.HasPrefix(got, "/") {
		t.Errorf("RelPath returned an absolute path: %q", got)
	}
	if strings.ContainsRune(got, '\\') {
		t.Errorf("RelPath must emit slash separated paths, got %q", got)
	}
	if want := "b/c/bom.json"; got != want {
		t.Errorf("RelPath = %q, want %q", got, want)
	}
}

// A relative base and a relative target are resolved against the same working
// directory, so the escape between them is expressed and not lost.
func TestRelPathRelativeEscape(t *testing.T) {
	got, err := index.RelPath("target/rio", "target/other/bom.json")
	if err != nil {
		t.Fatalf("RelPath: %v", err)
	}
	if want := "../other/bom.json"; got != want {
		t.Errorf("RelPath = %q, want %q", got, want)
	}
}
