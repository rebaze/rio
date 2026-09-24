package cli

import (
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/evidence"
	"os"
	"path/filepath"
	"testing"
)

func TestRecordJSONExecutionFailureAfterPublication(t *testing.T) {
	ip, _, _ := recordFixture(t)
	out := filepath.Join(t.TempDir(), "record.json")
	old := recordPublish
	defer func() { recordPublish = old }()
	recordPublish = func(path, indexPath string, journals []string, b []byte, v evidence.Validator, p ...evidence.RetryValidator) (evidence.Publication, error) {
		r, e := evidence.Publish(path, indexPath, journals, b, v, p...)
		if e != nil {
			return r, e
		}
		r.Output = nil
		return r, delivery.Fail("persistence_failed", "injected post-publication failure")
	}
	code, r, stderr := recordRun(t, "record", "--index", ip, "--output", out, "--quiet")
	if code != 3 || r["outputMayExist"] != true || r["output"] != nil || r["error"] == nil || stderr == "" {
		t.Fatal(code, r, stderr)
	}
	if _, e := os.Stat(out); e != nil {
		t.Fatal("published file deleted", e)
	}
}
