package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestLegacyClientBundleIsExplicitlyUnsupported(t *testing.T) {
	var out, stderr bytes.Buffer
	code := Main([]string{"record", "inspect", "--file", "testdata/oci-mixed-record.json", "--json"}, &out, &stderr)
	if code != ExitUsage || !strings.Contains(out.String()+stderr.String(), "rio-run-receipt") {
		t.Fatalf("legacy accepted/unclear: code=%d out=%s err=%s", code, out.String(), stderr.String())
	}
}
func TestPublicCommandsExposeNoBundleCollectionOrExport(t *testing.T) {
	for _, args := range [][]string{{"record", "--help"}, {"deliver", "--help"}} {
		var out, stderr bytes.Buffer
		if code := Main(args, &out, &stderr); code != 0 {
			t.Fatal(code, stderr.String())
		}
		for _, flag := range []string{"--evidence", "--delivery-record", "--batch", "--schema-version"} {
			if strings.Contains(out.String(), flag) {
				t.Errorf("retired export flag %s in %v", flag, args)
			}
		}
	}
}
