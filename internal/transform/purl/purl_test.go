package purl_test

import (
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/transform"
	_ "github.com/rebaze/rio/internal/transform/purl"
)

func TestRegisteredUnderTheManifestKey(t *testing.T) {
	var found bool
	for _, name := range transform.Known() {
		if name == "repair-purl" {
			found = true
		}
	}
	if !found {
		t.Fatalf("repair-purl not registered, known = %v", transform.Known())
	}
}

func TestDispatchToP2(t *testing.T) {
	tr, err := transform.New("repair-purl", transform.Config{"ecosystem": "p2"}, t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := tr.ID(); got != "repair-purl/p2" {
		t.Errorf("ID() = %q, want %q", got, "repair-purl/p2")
	}
}

func TestEcosystemErrors(t *testing.T) {
	cases := []struct {
		name          string
		cfg           transform.Config
		wantSubstring []string
	}{
		{"missing", transform.Config{}, []string{"ecosystem", "p2"}},
		{"empty", transform.Config{"ecosystem": ""}, []string{"ecosystem", "p2"}},
		{"unsupported", transform.Config{"ecosystem": "npm"}, []string{"npm", "p2"}},
		{"wrong type", transform.Config{"ecosystem": 2}, []string{"ecosystem"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := transform.New("repair-purl", tc.cfg, t.TempDir())
			if err == nil {
				t.Fatalf("want an error")
			}
			for _, want := range tc.wantSubstring {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to mention %q", err, want)
				}
			}
		})
	}
}

func TestUnknownConfigKeyIsRejected(t *testing.T) {
	_, err := transform.New("repair-purl", transform.Config{"ecosystem": "p2", "ecosytem": "p2"}, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "ecosytem") {
		t.Fatalf("err = %v, want it to name the typo", err)
	}
}

func TestTableIsResolvedRelativeToBaseDir(t *testing.T) {
	// A relative table path that does not exist under baseDir is a
	// configuration error naming the path (§10).
	_, err := transform.New("repair-purl",
		transform.Config{"ecosystem": "p2", "table": "mappings/absent.json"}, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "mappings/absent.json") {
		t.Fatalf("err = %v, want it to name the table path", err)
	}
}
