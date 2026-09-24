package cli

import (
	"bytes"
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"os"
	"path/filepath"
	"testing"
)

func TestOCIMixedPortableRecordFixture(t *testing.T) {
	path := "testdata/oci-mixed-record.json"
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	oldBuild, oldEnv := deliveryBuild, deliveryLookupEnv
	deliveryBuild = func(delivery.Provider, delivery.Description) (delivery.Target, error) {
		t.Fatal("portable fixture built a client")
		return nil, nil
	}
	deliveryLookupEnv = func(string) (string, bool) { t.Fatal("portable fixture resolved a credential"); return "", false }
	defer func() { deliveryBuild, deliveryLookupEnv = oldBuild, oldEnv }()
	var out, stderr bytes.Buffer
	if code := Main([]string{"record", "inspect", "--file", path, "--json"}, &out, &stderr); code != 0 {
		t.Fatal(code, stderr.String())
	}
	var result recordResult
	if e = json.Unmarshal(out.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if result.Record == nil || len(result.Record.Deliveries) != 2 {
		t.Fatal("mixed fixture missing deliveries")
	}
	for _, entry := range result.Record.Deliveries {
		if entry.Intent.Destination.Type == "oci" {
			if entry.Summary.Acknowledgment != "unknown" || entry.Summary.LatestVerification == nil || entry.Summary.LatestVerification.Observation.Value != "verified" || len(entry.Intent.ExpectedReferences) != 4 {
				t.Fatal("OCI facts conflated")
			}
		} else if entry.Summary.Acknowledgment != "accepted" || entry.Summary.LatestVerification != nil {
			t.Fatal("DTrack facts changed")
		}
	}
	var edited map[string]any
	json.Unmarshal(raw, &edited)
	edited["deliveries"].([]any)[0].(map[string]any)["summary"].(map[string]any)["acknowledgment"] = "invented"
	bad, _ := json.Marshal(edited)
	badPath := filepath.Join(t.TempDir(), "edited.json")
	os.WriteFile(badPath, bad, 0600)
	out.Reset()
	stderr.Reset()
	if code := Main([]string{"record", "inspect", "--file", badPath, "--json"}, &out, &stderr); code != 2 {
		t.Fatal("readable fact tamper accepted", code)
	}
}
