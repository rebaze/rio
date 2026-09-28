package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
)

func TestRecordReportOfflineExactDigestAndNoOverwrite(t *testing.T) {
	dir := project(t, tychoManifest, "tycho-rcp.cdx.json")
	requireExit(t, rio(t, dir, "normalize", "--gate", "fail", "--receipt", "record.json"), ExitOK)
	raw := append(readFile(t, dir, "record.json"), []byte("  \n")...)
	if err := os.WriteFile(filepath.Join(dir, "record.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(filepath.Join(dir, "target"))
	os.RemoveAll(filepath.Join(dir, "in"))
	os.Remove(filepath.Join(dir, "rio.yaml"))
	r := rio(t, dir, "record", "report", "--file", "record.json", "--output", "report.html")
	requireExit(t, r, ExitOK)
	html := readFile(t, dir, "report.html")
	for _, text := range []string{delivery.Digest(raw), "rcp-client", "repair-purl/p2", "applied 8", "unmapped 1", "Gate", "top-level"} {
		if !bytes.Contains(html, []byte(text)) {
			t.Errorf("report missing %q", text)
		}
	}
	requireExit(t, rio(t, dir, "record", "report", "--file", "record.json", "--output", "report.html"), ExitUsage)
	if !bytes.Equal(html, readFile(t, dir, "report.html")) {
		t.Fatal("report replaced")
	}
	if !bytes.Equal(raw, readFile(t, dir, "record.json")) {
		t.Fatal("source record changed")
	}
	human := rio(t, dir, "record", "inspect", "--file", "record.json")
	requireExit(t, human, ExitOK)
	for _, text := range []string{"repair-purl/p2", "applied=8", "unmapped=1", "gate=pass"} {
		if !strings.Contains(human.stdout, text) {
			t.Errorf("terminal omits shared fact %q: %s", text, human.stdout)
		}
	}
}

func TestRecordReportEscapesHTMLAndRejectsCorruption(t *testing.T) {
	dir := project(t, "version: 1\nartifacts:\n  - id: app\n    sbom: in/plain-maven.cdx.json\n    subject:\n      name: '<script>alert(1)</script>'\n      version: '1'\n", "plain-maven.cdx.json")
	requireExit(t, rio(t, dir, "normalize", "--receipt", "record.json"), ExitOK)
	requireExit(t, rio(t, dir, "record", "report", "--file", "record.json", "--output", "report.html"), ExitOK)
	html := string(readFile(t, dir, "report.html"))
	if strings.Contains(html, "<script>") || !strings.Contains(html, "&lt;script&gt;") {
		t.Fatal("unescaped supplied text")
	}
	for _, bad := range []string{"<script", "<iframe", "<img", "@import", "url(", "<link"} {
		if strings.Contains(strings.ToLower(html), bad) {
			t.Fatalf("network/script dependency: %s", bad)
		}
	}
	raw := readFile(t, dir, "record.json")
	raw = bytes.Replace(raw, []byte(`"schemaVersion": 1`), []byte(`"schemaVersion": 2`), 1)
	os.WriteFile(filepath.Join(dir, "bad.json"), raw, 0600)
	requireExit(t, rio(t, dir, "record", "report", "--file", "bad.json", "--output", "bad.html"), ExitUsage)
	if _, err := os.Stat(filepath.Join(dir, "bad.html")); !os.IsNotExist(err) {
		t.Fatal("rendered corrupt record")
	}
}
