package discover_test

import (
	"github.com/rebaze/rio/internal/discover"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestModulesSelectMarkersAndSortRoots(t *testing.T) {
	base := filepath.Join(t.TempDir(), "repo [literal] space")
	for _, p := range []string{"services/z-server/pom.xml", "services/a-server/other.xml", "services/a-server/pom.xml", "services/group/b-server/pom.xml", "services/client/pom.xml", "services/excluded-server/pom.xml"} {
		writeFile(t, base, p)
	}
	got, err := discover.Modules(base, "services/**/*server/*.xml", []string{"services/excluded-server/*"})
	if err != nil {
		t.Fatal(err)
	}
	want := []discover.Module{{Root: "services/a-server", Marker: "services/a-server/other.xml"}, {Root: "services/group/b-server", Marker: "services/group/b-server/pom.xml"}, {Root: "services/z-server", Marker: "services/z-server/pom.xml"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestModulesRefuseEmptyAndBadPatterns(t *testing.T) {
	base := t.TempDir()
	writeFile(t, base, "a/pom.xml")
	for _, tc := range []struct {
		pattern string
		exclude []string
	}{{"[", nil}, {"*/pom.xml", []string{"["}}, {"*/pom.xml", []string{"**"}}, {"absent/*", nil}} {
		if got, err := discover.Modules(base, tc.pattern, tc.exclude); err == nil || got != nil {
			t.Fatalf("Modules(%q,%v) = %v, %v", tc.pattern, tc.exclude, got, err)
		}
	}
}

func TestModulesSymlinks(t *testing.T) {
	for _, cycle := range []bool{false, true} {
		t.Run(map[bool]string{false: "alias", true: "cycle"}[cycle], func(t *testing.T) {
			base := t.TempDir()
			writeFile(t, base, "a/pom.xml")
			target := filepath.Join(base, "a")
			link := filepath.Join(base, "b")
			if cycle {
				target = base
				link = filepath.Join(base, "a", "loop")
			}
			if err := os.Symlink(target, link); err != nil {
				t.Skip(err)
			}
			got, err := discover.Modules(base, "**/pom.xml", nil)
			if err == nil || got != nil {
				t.Fatalf("partial/ambiguous result %v, %v", got, err)
			}
			if !cycle && !strings.Contains(err.Error(), "same physical") {
				t.Fatal(err)
			}
		})
	}
}

func TestModulesSingleSymlinkAndRegularMarkers(t *testing.T) {
	base := t.TempDir()
	real := t.TempDir()
	writeFile(t, real, "a/pom.xml")
	if err := os.Symlink(real, filepath.Join(base, "services")); err != nil {
		t.Skip(err)
	}
	makeDir(t, base, "directory/pom.xml")
	got, err := discover.Modules(base, "**/pom.xml", nil)
	if err != nil || len(got) != 1 || got[0].Root != "services/a" {
		t.Fatalf("%v, %v", got, err)
	}
}
