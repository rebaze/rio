package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/rebaze/rio/internal/receipt"
)

func TestStandaloneIntakeFailurePublishesScopedReceipt(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "digest"}[corrupt], func(t *testing.T) {
			dir := batchFixture(t, "https://unused.invalid")
			t.Chdir(dir)
			path := filepath.Join("target", "rio", "worker.json")
			if corrupt {
				if e := os.WriteFile(path, []byte(`{}`), 0600); e != nil {
					t.Fatal(e)
				}
			} else if e := os.Remove(path); e != nil {
				t.Fatal(e)
			}
			code, result, _ := runBatch(t, "deliver", "--receipt", "failed.json")
			raw, e := os.ReadFile("failed.json")
			if code != 2 || e != nil {
				t.Fatalf("code=%d result=%v receipt=%v", code, result, e)
			}
			d, e := receipt.Parse(raw)
			if e != nil {
				t.Fatal(e)
			}
			if d.Run.Outcome != "failed" || d.Run.Stages["intake"] != "failed" || d.Run.Stages["delivery"] != "not-attempted" || len(d.Artifacts) != 3 || len(d.Deliveries) != 3 {
				t.Fatalf("scope: %#v", d)
			}
			for i, state := range []string{"completed", "failed", "not-attempted"} {
				a := d.Artifacts[i]
				if a.State != state || !a.PreExisting || (i == 0) != (a.Input != nil) {
					t.Fatalf("artifact %d: %#v", i, a)
				}
			}
			for _, v := range d.Deliveries {
				if v.State != "unattempted" || v.RequestMayHaveOccurred {
					t.Fatalf("invented delivery: %#v", v)
				}
			}
		})
	}
}

func TestReconcileTLSFailureRetainsBothObservationsAndRecovery(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			io.Copy(io.Discard, r.Body)
			io.WriteString(w, `{"token":"11111111-1111-4111-8111-111111111111"}`)
			return
		}
		// Finish this response but make the next poll fail before a TLS handshake.
		w.Header().Set("Connection", "close")
		io.WriteString(w, `{"processing":true}`)
		srv.Listener.Close()
	}))
	defer srv.Close()
	dir := batchFixture(t, srv.URL)
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "synthetic")
	cfg, _ := os.ReadFile("rio.yaml")
	os.WriteFile("rio.yaml", bytes.ReplaceAll(cfg, []byte("allowHTTP: true"), []byte("insecureSkipVerify: true")), 0600)
	code, result, _ := runBatch(t, "deliver", "--artifact", "app")
	if code != 0 {
		t.Fatal(code, result)
	}
	journal := result["items"].([]any)[0].(map[string]any)["record"].(string)
	var out, stderr bytes.Buffer
	code = Main([]string{"delivery", "reconcile", "--record", journal, "--wait", "4s", "--json"}, &out, &stderr)
	var r struct {
		Receipt receipt.Publication `json:"receipt"`
	}
	json.Unmarshal(out.Bytes(), &r)
	raw, e := os.ReadFile(r.Receipt.Path)
	if code == 0 || e != nil {
		t.Fatalf("code=%d read=%v out=%s err=%s", code, e, out.String(), stderr.String())
	}
	d, e := receipt.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	check := func(d receipt.Document) {
		t.Helper()
		v := d.Deliveries[0]
		if len(v.Responses) != 2 || v.Transport.TLSObserved == nil || !*v.Transport.TLSObserved || v.Responses[0].HTTPStatus != 200 || v.Responses[1].Kind != "unavailable" {
			t.Fatalf("lost facts: %#v", v)
		}
		// Decode response facts without requiring the new Go field for the red test.
		b, _ := json.Marshal(v.Responses)
		var rs []map[string]any
		json.Unmarshal(b, &rs)
		if rs[0]["tlsObserved"] != true || rs[1]["tlsObserved"] != false {
			t.Fatalf("per-response TLS: %s", b)
		}
	}
	check(d)
	entries, _ := filepath.Glob(filepath.Join(filepath.Dir(r.Receipt.Path), ".internal", "checkpoint-*.json"))
	sort.Strings(entries)
	// Retain the before-poll checkpoint; recover both observations from the journal.
	for len(entries) > 0 {
		last := entries[len(entries)-1]
		b, _ := os.ReadFile(last)
		cp, e := receipt.Parse(b)
		if e != nil {
			t.Fatal(e)
		}
		if cp.Run.Outcome == "incomplete" && len(cp.Deliveries[0].Responses) == 0 {
			break
		}
		if e := os.Remove(last); e != nil {
			t.Fatal(e)
		}
		entries = entries[:len(entries)-1]
	}
	recovered, e := recoverInvocation(filepath.Dir(r.Receipt.Path))
	if e != nil {
		t.Fatal(e)
	}
	check(recovered)
	if recovered.Run.Outcome != "incomplete" {
		t.Fatal("recovery claimed completion")
	}
}

func TestReconcileDefaultOutputCannotMutateInvalidSourceJournal(t *testing.T) {
	dir := batchFixture(t, "https://unused.invalid")
	t.Chdir(dir)
	if e := os.Mkdir("prior", 0700); e != nil {
		t.Fatal(e)
	}
	var out, stderr bytes.Buffer
	if code := Main([]string{"delivery", "reconcile", "--record", "prior", "--out", "prior", "--json"}, &out, &stderr); code == 0 {
		t.Fatal("accepted invalid journal")
	}
	entries, e := os.ReadDir("prior")
	if e != nil || len(entries) != 0 {
		t.Fatalf("mutated source journal: %v %v", entries, e)
	}
}
