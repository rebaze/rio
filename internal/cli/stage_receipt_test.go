package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/rebaze/rio/internal/receipt"
)

func TestStandaloneDeliverOwnsScopedReceipt(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"11111111-1111-4111-8111-111111111111"}`)
	}))
	defer srv.Close()
	dir := batchFixture(t, srv.URL)
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "synthetic")
	var out, stderr bytes.Buffer
	code := Main([]string{"deliver", "--artifact", "app", "--json"}, &out, &stderr)
	var result struct {
		Receipt receipt.Publication `json:"receipt"`
	}
	if e := json.Unmarshal(out.Bytes(), &result); e != nil || code != 0 || result.Receipt.Path == "" {
		t.Fatalf("code=%d out=%s err=%s parse=%v", code, out.String(), stderr.String(), e)
	}
	raw, e := os.ReadFile(result.Receipt.Path)
	if e != nil {
		t.Fatal(e)
	}
	d, e := receipt.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	if d.Run.Operation != "deliver" || len(d.Artifacts) != 1 || !d.Artifacts[0].PreExisting || d.Artifacts[0].Changes != nil || d.Artifacts[0].Input.SHA256 != d.Artifacts[0].Output.SHA256 || len(d.Deliveries) != 1 || d.Deliveries[0].State != "accepted" || calls != 1 {
		t.Fatalf("not scoped: %#v", d)
	}
	// A new public receipt is not authorization to duplicate an existing upload.
	out.Reset()
	stderr.Reset()
	if code = Main([]string{"deliver", "--artifact", "app", "--json"}, &out, &stderr); code == 0 || calls != 1 {
		t.Fatalf("duplicate code=%d calls=%d", code, calls)
	}
}
func TestStandaloneDeliveryReceiptReservedBeforeUpload(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer srv.Close()
	dir := batchFixture(t, srv.URL)
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "synthetic")
	os.WriteFile("prior.json", []byte("immutable"), 0600)
	var out, stderr bytes.Buffer
	if code := Main([]string{"deliver", "--receipt", "prior.json", "--json"}, &out, &stderr); code == 0 || calls != 0 {
		t.Fatalf("code=%d calls=%d", code, calls)
	}
	raw, _ := os.ReadFile("prior.json")
	if string(raw) != "immutable" {
		t.Fatal("overwritten")
	}
}

func TestReconciliationReceiptKeepsPriorHistorySeparate(t *testing.T) {
	uploads, observations := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			uploads++
			io.WriteString(w, `{"token":"11111111-1111-4111-8111-111111111111"}`)
		} else {
			observations++
			io.WriteString(w, `{"processing":false}`)
		}
	}))
	defer srv.Close()
	dir := batchFixture(t, srv.URL)
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "synthetic")
	code, result, _ := runBatch(t, "deliver", "--artifact", "app")
	if code != 0 {
		t.Fatal(code, result)
	}
	firstPath := result["receipt"].(map[string]any)["path"].(string)
	first, _ := os.ReadFile(firstPath)
	journal := result["items"].([]any)[0].(map[string]any)["record"].(string)
	var out, stderr bytes.Buffer
	code = Main([]string{"delivery", "reconcile", "--record", journal, "--json"}, &out, &stderr)
	var rr struct {
		Receipt receipt.Publication `json:"receipt"`
	}
	if e := json.Unmarshal(out.Bytes(), &rr); e != nil || code != 0 || rr.Receipt.Path == "" {
		t.Fatalf("code=%d out=%s err=%s parse=%v", code, out.String(), stderr.String(), e)
	}
	raw, _ := os.ReadFile(rr.Receipt.Path)
	d, e := receipt.Parse(raw)
	if e != nil {
		t.Fatalf("%v %s", e, raw)
	}
	if d.Run.Operation != "reconcile" || len(d.Deliveries) != 1 || d.Deliveries[0].Prior == nil || len(d.Deliveries[0].Responses) != 1 || d.Deliveries[0].Responses[0].Kind != "activity" || d.Deliveries[0].Responses[0].Value != "not-observed" || len(d.Deliveries[0].Submitted) != 0 || uploads != 1 || observations != 1 {
		t.Fatalf("not scoped: %#v uploads=%d observations=%d", d, uploads, observations)
	}
	unchanged, _ := os.ReadFile(firstPath)
	if !bytes.Equal(first, unchanged) {
		t.Fatal("prior receipt changed")
	}
}
