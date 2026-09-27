package p2_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/rebaze/rio/internal/transform"
)

// Resolution precedence must be visible, and the digest must bind the bytes
// loaded by New even when the table changes before Apply.
func TestResolutionProvenance(t *testing.T) {
	table := []byte(`{"schemaVersion":1,"entries":{"com.google.gson":{"groupId":"override","artifactId":"gson","confidence":"manifest-proven","evidence":"synthetic assertion"}}}`)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "table.json"), table, 0600); err != nil {
		t.Fatal(err)
	}
	tr := newTransform(t, transform.Config{"table": "table.json"}, dir)
	if err := os.WriteFile(filepath.Join(dir, "table.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, qualifiers, properties, kind, selector string }{
		{"qualifier wins", "&maven-groupId=input&maven-artifactId=gson", properties("maven-groupId", "property", "maven-artifactId", "gson"), "input-qualifier", "maven-groupid,maven-artifactid"},
		{"property wins", "", properties("maven.groupId", "property", "maven.artifactId", "gson"), "component-property", "maven.groupId,maven.artifactId"},
		{"override wins", "", "", "external-table-entry", "/entries/com.google.gson"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := load(t, source(bundle("com.google.gson", "2.8.9.today", tc.qualifiers, tc.properties)))
			res, err := tr.Apply(doc)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Changes) != 1 {
				t.Fatalf("one purl rewrite, got %+v", res)
			}
			data, _ := json.Marshal(res.Changes[0])
			var change map[string]any
			json.Unmarshal(data, &change)
			p, ok := change["resolution"].(map[string]any)
			if !ok {
				t.Fatalf("resolution provenance missing: %s", data)
			}
			if p["kind"] != tc.kind || p["selector"] != tc.selector {
				t.Fatalf("wrong source: %v", p)
			}
			if tc.kind == "external-table-entry" {
				if p["sha256"] != fmt.Sprintf("%x", sha256.Sum256(table)) {
					t.Fatalf("digest is not the loaded table bytes: %v", p)
				}
				m, _ := p["metadata"].(map[string]any)
				if m["confidence"] != "manifest-proven" || m["evidence"] != "synthetic assertion" {
					t.Fatalf("categorical assertions lost: %v", p)
				}
			} else if p["sha256"] != nil {
				t.Fatalf("input evidence falsely attributed to table: %v", p)
			}
		})
	}
}

func TestBuiltinAndQualifierOnlyProvenance(t *testing.T) {
	for _, tc := range []struct{ name, kind string }{{"com.google.gson", "built-in-entry"}, {"unmapped.bundle", "input-version"}} {
		res, _, _ := run(t, nil, source(bundle(tc.name, "1.2.3.today", "", "")))
		data, _ := json.Marshal(res.Changes[0])
		var c map[string]any
		json.Unmarshal(data, &c)
		p, _ := c["resolution"].(map[string]any)
		if p["kind"] != tc.kind {
			t.Fatalf("%s source = %s", tc.name, data)
		}
		if tc.kind == "built-in-entry" && (p["sha256"] == nil || p["metadata"] != nil) {
			t.Fatalf("built-in digest or absent metadata incorrect: %v", p)
		}
	}
}
