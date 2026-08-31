package sbom_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rebaze/rio/internal/sbom"
)

// FuzzLoad drives the CycloneDX decoder with arbitrary bytes. Load is rio's
// only entry point for documents it did not write, so it is the one place
// where a malformed file reaches the tool before any validation has happened.
//
// The property under test is not "does not panic" alone. A Document that Load
// accepted has to stay usable: every accessor a transform reaches for must
// work on it, and it must survive a round trip, because rio writes documents
// back out and a document it cannot re-read is one it has corrupted.
func FuzzLoad(f *testing.F) {
	seeds, err := filepath.Glob(filepath.Join("..", "..", "testdata", "*.cdx.json"))
	if err != nil {
		f.Fatalf("glob seed corpus: %v", err)
	}
	if len(seeds) == 0 {
		f.Fatal("no seed corpus found in testdata")
	}
	for _, name := range seeds {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatalf("read seed %s: %v", name, err)
		}
		f.Add(data)
	}
	// Shapes the fixtures do not cover: the empty input, a bare document with
	// no components, and the two ways bomFormat can be wrong.
	f.Add([]byte(``))
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`))
	f.Add([]byte(`{"bomFormat":"SPDX","specVersion":"1.5"}`))
	f.Add([]byte(`{"specVersion":"1.5","components":[{"name":"a"}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := sbom.Load(data)
		if err != nil {
			if doc != nil {
				t.Fatalf("Load returned both a document and an error %v", err)
			}
			return
		}
		if doc == nil {
			t.Fatal("Load returned no document and no error")
		}
		// Load's contract: it fails unless the bytes are a CycloneDX document,
		// which means specVersion was present and non-empty.
		if doc.SpecVersion() == "" {
			t.Fatal("Load accepted a document with an empty specVersion")
		}

		// Every accessor a transform reaches for, on a document rio did not write.
		n := doc.ComponentCount()
		if n < 0 {
			t.Fatalf("ComponentCount is negative: %d", n)
		}
		for i := range n {
			if doc.Component(i) == nil {
				t.Fatalf("Component(%d) is nil while ComponentCount is %d", i, n)
			}
		}
		if got := len(doc.Components()); got != n {
			t.Fatalf("Components() has %d entries, ComponentCount is %d", got, n)
		}
		for _, c := range doc.Components() {
			_, _, _, _ = c.Name(), c.Version(), c.PURL(), c.Group()
			_ = c.Properties()
			_ = c.BOMRef()
		}
		_ = doc.Fingerprint()
		_, _ = doc.Subject()
		_ = doc.IntegrityFindings()

		// Round trip. rio writes documents back out, so one it can serialize
		// but not re-read would be one it silently corrupted.
		out, err := doc.Bytes()
		if err != nil {
			return // Serialization may legitimately refuse; that is not corruption.
		}
		again, err := sbom.Load(out)
		if err != nil {
			t.Fatalf("document did not survive a round trip: %v\noutput: %q", err, out)
		}
		if again.SpecVersion() != doc.SpecVersion() {
			t.Fatalf("specVersion changed across a round trip: %q became %q",
				doc.SpecVersion(), again.SpecVersion())
		}
		if got := again.ComponentCount(); got != n {
			t.Fatalf("component count changed across a round trip: %d became %d", n, got)
		}
	})
}
