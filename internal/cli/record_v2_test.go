package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRecordExplicitVersion2AndOldDefault(t *testing.T) {
	ip, p, q := recordFixture(t)
	dir := t.TempDir()
	r := rio(t, dir, "record", "--schema-version", "2", "--index", ip, "--delivery-record", p, "--delivery-record", q, "--output", "v2.json")
	requireExit(t, r, ExitOK)
	data := readFile(t, dir, "v2.json")
	doc := decode(t, data)
	if doc["schemaVersion"] != json.Number("2") || doc["expectedScope"] != "not-recorded" {
		t.Fatal(doc)
	}
	os.RemoveAll(filepath.Dir(ip))
	os.RemoveAll(filepath.Dir(p))
	os.RemoveAll(filepath.Dir(q))
	requireExit(t, rio(t, dir, "record", "inspect", "--file", "v2.json"), ExitOK)
}
