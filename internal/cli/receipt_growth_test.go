package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestReceiptSizeDoesNotCopyInventoryOrBulkLedger(t *testing.T) {
	for _, repair := range []bool{false, true} {
		t.Run(fmt.Sprint(repair), func(t *testing.T) {
			dir := pipelineFixture(t, "")
			t.Chdir(dir)
			if repair {
				raw, _ := os.ReadFile("rio.yaml")
				raw = bytes.Replace(raw, []byte("    sbom: api.cdx.json"), []byte("    sbom: api.cdx.json\n    transforms: [{repair-purl: {ecosystem: p2}}]"), 1)
				os.WriteFile("rio.yaml", raw, 0600)
			}
			sizes := []int{}
			for _, count := range []int{1, 600} {
				components := make([]map[string]any, count)
				for i := range components {
					c := map[string]any{"bom-ref": fmt.Sprintf("component-%d", i), "type": "library", "name": fmt.Sprintf("inventory-only-%d", i), "version": "1", "purl": "pkg:maven/example/lib@1"}
					if repair {
						c["group"] = "p2.eclipse.plugin"
						c["name"] = "org.eclipse.osgi"
						c["version"] = "3.18.600.v20231110-1900"
						c["purl"] = "pkg:p2/org.eclipse.osgi@3.18.600.v20231110-1900?classifier=osgi.bundle"
					}
					components[i] = c
				}
				input := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "metadata": map[string]any{"component": map[string]string{"type": "application", "name": "api", "version": "1"}}, "components": components}
				raw, _ := json.Marshal(input)
				os.WriteFile("api.cdx.json", raw, 0600)
				code, d, path := rootReceipt(t, "--artifact", "api")
				if code != 0 {
					t.Fatal(code)
				}
				receiptBytes, _ := os.ReadFile(path)
				sizes = append(sizes, len(receiptBytes))
				if bytes.Contains(receiptBytes, []byte("inventory-only-")) || bytes.Contains(receiptBytes, []byte("/components/")) {
					t.Fatal("copied per-component inventory/ledger")
				}
				if repair {
					b := d.Artifacts[0].Changes.Bulk
					if len(b) != 1 || b[0].Evaluated != count || b[0].Applied != count || b[0].Unmapped != 0 || b[0].Skipped != 0 {
						t.Fatalf("bulk counters %#v", b)
					}
				}
			}
			if sizes[1]-sizes[0] > 128 {
				t.Fatalf("receipt grew with inventory: %v", sizes)
			}
		})
	}
}
func TestDefaultContextValueIsNotClaimedSuppliedByFile(t *testing.T) {
	dir, one, two := contextProject(t)
	writeContextFile(t, dir, one, two)
	t.Chdir(dir)
	code, d, _ := rootReceipt(t, "normalize")
	if code != 0 {
		t.Fatal(code)
	}
	found := 0
	for _, a := range d.Artifacts {
		for _, c := range a.Changes.Metadata {
			if c.Field == "source.workspace" {
				found++
				if c.Source != "context-default" || c.After != "unknown" {
					t.Fatalf("default misattributed: %#v", c)
				}
			}
		}
	}
	if found != 2 {
		t.Fatal("missing default metadata assertions")
	}
}
