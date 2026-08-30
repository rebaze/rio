package index_test

import (
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

// TestRelPathRefusesEscape backs §7: an index that names a path outside the
// directory it is relative to is not portable, so refuse it loudly.
func TestRelPathRefusesEscape(t *testing.T) {
	tests := []struct {
		name   string
		base   string
		target string
	}{
		{"sibling directory", "/repo/target/rio", "/repo/rio.yaml"},
		{"different root", "/repo", "/elsewhere/bom.json"},
		{"parent", "/repo/sub", "/repo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := index.RelPath(tt.base, tt.target)
			if err == nil {
				t.Fatalf("RelPath(%q, %q) = %q, want an error", tt.base, tt.target, got)
			}
			if !strings.Contains(err.Error(), "outside") {
				t.Errorf("error must say the path escapes, got %v", err)
			}
			if !strings.Contains(err.Error(), tt.target) {
				t.Errorf("error must name the offending path, got %v", err)
			}
			if got != "" {
				t.Errorf("a refused path must return %q, got %q", "", got)
			}
		})
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

// A relative base is resolved against the process working directory, so a
// relative target that lands outside it is still caught.
func TestRelPathRelativeEscape(t *testing.T) {
	if _, err := index.RelPath("target/rio", "target/other/bom.json"); err == nil {
		t.Error("a relative target outside the base must be refused")
	}
}
