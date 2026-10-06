package cli

import (
	"bytes"
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestStandaloneNormalizeReceiptAndOutputsAreIsolated(t *testing.T) {
	dir := pipelineFixture(t, "https://unused.invalid")
	t.Chdir(dir)
	old := deliveryBuild
	deliveryBuild = func(delivery.Provider, delivery.Description) (delivery.Target, error) {
		t.Fatal("normalize built client")
		return nil, nil
	}
	defer func() { deliveryBuild = old }()
	code, first, firstPath := rootReceipt(t, "normalize", "--attest")
	if code != 0 || first.Run.Operation != "normalize" || len(first.Deliveries) != 0 || first.Run.Stages["delivery"] != "not-applicable" || len(first.Artifacts) != 2 {
		t.Fatalf("%d %#v", code, first)
	}
	for _, name := range []string{"index.json", "api.cdx.json", "worker.cdx.json", "api.intoto.json"} {
		if _, e := os.Stat(filepath.Join(filepath.Dir(firstPath), name)); e != nil {
			t.Fatal(e)
		}
	}
	code, second, secondPath := rootReceipt(t, "normalize")
	if code != 0 || firstPath == secondPath || first.Run.ID == second.Run.ID {
		t.Fatal("shared run")
	}
	if _, e := os.Stat("target/rio/api.cdx.json"); !os.IsNotExist(e) {
		t.Fatal("mutable singleton output")
	}
}

func TestStandaloneDeliveryReceiptRetainsFilteredScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"11111111-1111-4111-8111-111111111111"}`)
	}))
	defer srv.Close()
	dir := batchFixture(t, srv.URL)
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "synthetic")
	f, _ := os.OpenFile("rio.yaml", os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString("    other:\n      type: dependency-track\n      url: https://unused.example.org\n")
	f.Close()
	code, result, _ := runBatch(t, "deliver", "--artifact", "app", "--target", "security")
	if code != 0 {
		t.Fatal(code)
	}
	raw, _ := os.ReadFile(result["receipt"].(map[string]any)["path"].(string))
	d, e := receipt.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	if len(d.Targets) != 2 || len(d.Exclusions) != 3 || d.Run.Overrides["artifact"] != "[app]" || d.Run.Overrides["target"] != "[security]" {
		t.Fatalf("scope omitted: %#v", d)
	}
}

func TestReceiptDestinationCannotCorruptPriorJournal(t *testing.T) {
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
	code, _, _ := runBatch(t, "deliver", "--artifact", "app", "--record", "prior")
	if code != 0 {
		t.Fatal(code)
	}
	before, e := record.Read("prior")
	if e != nil {
		t.Fatal(e)
	}
	code, _, _ = runBatch(t, "deliver", "--artifact", "app", "--record", "retry", "--retry-of", "prior", "--receipt", filepath.Join("prior", "receipt.json"))
	after, e := record.Read("prior")
	if code != ExitUsage || calls != 1 || e != nil || before.SHA256 != after.SHA256 {
		t.Fatalf("receipt damaged prior journal: code=%d requests=%d error=%v", code, calls, e)
	}
	if _, e = os.Stat(filepath.Join("prior", "receipt.json")); !os.IsNotExist(e) {
		t.Fatal("published inside journal")
	}
	code, _, _ = runBatch(t, "deliver", "--artifact", "app", "--record", "fresh", "--out", "prior")
	after, e = record.Read("prior")
	if code != ExitUsage || e != nil || after.SHA256 != before.SHA256 || calls != 1 {
		t.Fatal("output root damaged prior journal", code, e, calls)
	}
}
func TestReceiptDestinationCannotOccupyFutureJournalSlot(t *testing.T) {
	dir := batchFixture(t, "https://receiver.example.org")
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "synthetic")
	_, plan, e := batchPreflight("rio.yaml", deliveryOptions{index: "target/rio/index.json", artifacts: []string{"app"}})
	if e != nil {
		t.Fatal(e)
	}
	slot := plan.Jobs[0].Record
	os.MkdirAll(filepath.Dir(slot), 0700)
	code, _, _ := runBatch(t, "deliver", "--artifact", "app", "--receipt", slot)
	if code != ExitUsage {
		t.Fatal(code)
	}
	if _, e = os.Stat(slot); !os.IsNotExist(e) {
		t.Fatal("receipt occupied a reserved attempt namespace")
	}
}
