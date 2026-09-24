//go:build unix

package discover_test

import (
	"github.com/rebaze/rio/internal/discover"
	"testing"
)

func TestModulesIncompleteSearch(t *testing.T) {
	base := t.TempDir()
	writeFile(t, base, "services/a/pom.xml")
	makeUnreadable(t, base, "services/secret")
	if got, err := discover.Modules(base, "services/**/pom.xml", nil); err == nil || got != nil {
		t.Fatalf("partial result %v, %v", got, err)
	}
	// A narrower search does not visit the unreadable sibling.
	if _, err := discover.Modules(base, "services/a/pom.xml", nil); err != nil {
		t.Fatal(err)
	}
}

func TestModulesNamedPipe(t *testing.T) {
	base := t.TempDir()
	makeFifo(t, base, "a/pom.xml")
	if _, err := discover.Modules(base, "*/pom.xml", nil); err == nil {
		t.Fatal("named pipe selected as marker")
	}
}
