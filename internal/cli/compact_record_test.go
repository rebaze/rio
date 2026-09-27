package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/receipt"
)

func TestCompactInspectAndReportWithoutWorkspace(t *testing.T) {
	dir := pipelineFixture(t, "")
	t.Chdir(dir)
	_, _, path := rootReceipt(t)
	raw, _ := os.ReadFile(path)
	published := t.TempDir()
	file := filepath.Join(published, "record.json")
	os.WriteFile(file, raw, 0600)
	t.Chdir(published)
	os.RemoveAll(dir)
	old := deliveryBuild
	deliveryBuild = func(delivery.Provider, delivery.Description) (delivery.Target, error) {
		t.Fatal("offline client construction")
		return nil, nil
	}
	defer func() { deliveryBuild = old }()
	for _, args := range [][]string{{"record", "inspect", "--file", file, "--json"}, {"record", "report", "--file", file, "--output", filepath.Join(published, "report.html"), "--json"}} {
		var out, stderr bytes.Buffer
		if code := Main(args, &out, &stderr); code != 0 {
			t.Fatalf("%v code=%d out=%s err=%s", args, code, out.String(), stderr.String())
		}
	}
	html, _ := os.ReadFile(filepath.Join(published, "report.html"))
	if !bytes.Contains(html, []byte(delivery.Digest(raw))) || !bytes.Contains(html, []byte("api.cdx.json")) {
		t.Fatal("report missing identity")
	}
	entries, _ := os.ReadDir(published)
	if len(entries) != 2 {
		t.Fatalf("read-only commands created execution state: %v", entries)
	}
}
func TestRecordRecoverWritesFreshSnapshotOnly(t *testing.T) {
	dir := pipelineFixture(t, "")
	t.Chdir(dir)
	_, prior, path := rootReceipt(t)
	dest := filepath.Join(t.TempDir(), "recovered.json")
	var out, stderr bytes.Buffer
	if code := Main([]string{"record", "recover", "--run", filepath.Dir(path), "--output", dest, "--json"}, &out, &stderr); code != 0 {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), stderr.String())
	}
	raw, e := os.ReadFile(dest)
	if e != nil {
		t.Fatal(e)
	}
	recovered, e := receipt.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	if recovered.Run.ID != prior.Run.ID || recovered.Run.FinishedAt != prior.Run.FinishedAt {
		t.Fatal("invented invocation")
	}
	out.Reset()
	stderr.Reset()
	if code := Main([]string{"record", "recover", "--run", filepath.Dir(path), "--output", dest}, &out, &stderr); code == 0 {
		t.Fatal("overwrote recovered snapshot")
	}
}
