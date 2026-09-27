package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/batchrecord"
	"github.com/rebaze/rio/internal/evidence"
	"github.com/spf13/cobra"
)

func TestBatchEvidenceBeforeRequestsAndPartialReturn(t *testing.T) {
	calls := 0
	var dir string
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		io.Copy(io.Discard, r.Body)
		raw, e := os.ReadFile(filepath.Join(dir, "record.json.batch.json"))
		if e != nil {
			t.Error("request before durable descriptor", e)
			return
		}
		d, e := batchrecord.ParseDescriptor(raw)
		if e != nil {
			t.Error(e)
			return
		}
		if e = batchrecord.ValidateIndex(d, captured); e != nil {
			t.Error(e)
		}
		if _, e = os.Stat(filepath.Join(dir, "record.json.batch-result.json")); !os.IsNotExist(e) {
			t.Error("completion before return")
		}
		// The live index may be overwritten while requests are in flight.
		os.WriteFile(filepath.Join(dir, "target/rio/index.json"), []byte(`{}`), 0600)
		w.Header().Set("Content-Type", "application/json")
		if calls == 2 {
			io.WriteString(w, `{}`)
		} else {
			io.WriteString(w, `{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}`)
		}
	}))
	defer srv.Close()
	dir = batchFixture(t, srv.URL)
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "SYNTHETIC_SECRET_CANARY_BATCH")
	captured, _ = os.ReadFile("target/rio/index.json")
	c := &batchCapture{Output: "record.json"}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	r, e := executeDeliverBatch(cmd, &globalOptions{manifest: "rio.yaml"}, deliveryOptions{index: "target/rio/index.json"}, c)
	if e == nil || r.ExitCode != 4 || r.Outcome != "partial" || calls != 2 {
		t.Fatal(r, e, calls)
	}
	saved, _ := os.ReadFile("record.json.index.json")
	if !bytes.Equal(saved, captured) {
		t.Fatal("snapshot changed")
	}
	raw, e := os.ReadFile("record.json.batch.json")
	if e != nil {
		t.Fatal(e)
	}
	d, e := batchrecord.ParseDescriptor(raw)
	if e != nil {
		t.Fatal(e)
	}
	completion, e := os.ReadFile("record.json.batch-result.json")
	if e != nil {
		t.Fatal(e)
	}
	end, e := batchrecord.ParseCompletion(completion, d, raw)
	if e != nil {
		t.Fatal(e)
	}
	if end.Items[0].Acknowledgment != "accepted" || end.Items[1].Acknowledgment != "unknown" || end.Items[2].State != "unattempted" {
		t.Fatal(end)
	}
	for _, data := range [][]byte{raw, completion, saved} {
		if bytes.Contains(data, []byte("SYNTHETIC_SECRET_CANARY_BATCH")) {
			t.Fatal("secret in evidence")
		}
	}
}

func TestBatchEvidencePreflightAndCompletionFailureNeverRetry(t *testing.T) {
	for _, when := range []string{"existing-output", "existing-descriptor", "completion-write"} {
		t.Run(when, func(t *testing.T) {
			calls := 0
			var dir string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				io.Copy(io.Discard, r.Body)
				if when == "completion-write" {
					os.Mkdir(filepath.Join(dir, "record.json.batch-result.json"), 0700)
				}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}`)
			}))
			defer srv.Close()
			dir = batchFixture(t, srv.URL)
			t.Chdir(dir)
			t.Setenv("DTRACK_API_KEY", "synthetic-key")
			if when == "existing-output" {
				os.WriteFile("record.json", []byte("keep"), 0600)
			}
			if when == "existing-descriptor" {
				os.WriteFile("record.json.batch.json", []byte("keep"), 0600)
			}
			c := &batchCapture{Output: "record.json"}
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			r, e := executeDeliverBatch(cmd, &globalOptions{manifest: "rio.yaml"}, deliveryOptions{index: "target/rio/index.json"}, c)
			if e == nil {
				t.Fatal("persistence failure ignored")
			}
			if when == "completion-write" {
				if calls != 3 || r.ExitCode != 3 || !r.RequestMayHaveOccurred {
					t.Fatal(r, e, calls)
				}
			} else if calls != 0 {
				t.Fatal("preflight sent request", calls)
			}
			b, _ := json.Marshal(r)
			if bytes.Contains(b, []byte("synthetic-key")) {
				t.Fatal("secret in result")
			}
		})
	}
}

func TestDeliverEvidencePublicWorkflow(t *testing.T) {
	for _, mode := range []string{"accepted", "rejected", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "accepted":
					io.WriteString(w, `{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}`)
				case "rejected":
					w.WriteHeader(403)
				default:
					io.WriteString(w, `{}`)
				}
			}))
			defer srv.Close()
			dir := batchFixture(t, srv.URL)
			t.Chdir(dir)
			t.Setenv("DTRACK_API_KEY", "synthetic-public-key")
			r := rio(t, dir, "deliver", "--evidence", "record.json", "--json")
			want := ExitOK
			if mode == "rejected" {
				want = 5
			}
			if mode == "unknown" {
				want = 4
			}
			requireExit(t, r, want)
			var result map[string]any
			if err := json.Unmarshal([]byte(r.stdout), &result); err != nil {
				t.Fatal(err)
			}
			if result["schemaVersion"] != float64(3) || result["evidence"] == nil {
				t.Fatal("evidence CLI result not separately versioned", result)
			}
			raw := readFile(t, dir, "record.json")
			if doc := decode(t, raw); doc["schemaVersion"] != json.Number("2") {
				t.Fatal(doc)
			}
			expected := 3
			if mode != "accepted" {
				expected = 1
			}
			if calls != expected {
				t.Fatal("unexpected retry", calls)
			}
			srv.Close()
			requireExit(t, rio(t, dir, "record", "inspect", "--file", "record.json"), ExitOK)
			// Offline recovery follows the retained snapshot after the working index changes.
			os.WriteFile("target/rio/index.json", []byte(`{}`), 0600)
			requireExit(t, rio(t, dir, "record", "--schema-version", "2", "--batch", "record.json.batch.json", "--output", "after.json"), ExitOK)
		})
	}
}

func TestEvidencePublicationFailurePreservesDeliveryAndOfflineRecovery(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}`)
	}))
	defer srv.Close()
	dir := batchFixture(t, srv.URL)
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "synthetic-key")
	original := publishAutomaticEvidence
	defer func() { publishAutomaticEvidence = original }()
	publishAutomaticEvidence = func(res *batchrecord.Reservation, raw []byte) (evidence.Publication, error) {
		p, e := original(res, raw)
		if e != nil {
			return p, e
		}
		p.Output = nil
		return p, delivery.Fail("persistence_failed", "injected after successful publication")
	}
	r := rio(t, dir, "deliver", "--evidence", "record.json", "--json")
	requireExit(t, r, 3)
	m := decode(t, []byte(r.stdout))
	v := m["evidence"].(map[string]any)
	if calls != 3 || m["delivery"].(map[string]any)["outcome"] != "accepted" || m["requestMayHaveOccurred"] != true || v["outputMayExist"] != true || v["output"] != nil {
		t.Fatal("lost delivery outcome or falsely claimed publication", m, calls)
	}
	srv.Close()
	args := []string{}
	for i, a := range v["recoveryCommand"].([]any) {
		if i > 0 {
			args = append(args, a.(string))
		}
	}
	requireExit(t, rio(t, dir, args...), ExitOK)
	if calls != 3 {
		t.Fatal("recovery retried upload")
	}
}

func TestEvidenceEmptyAndExistingOutputRefuseBeforeRequests(t *testing.T) {
	for _, kind := range []string{"empty", "existing"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}`)
			}))
			defer srv.Close()
			dir := batchFixture(t, srv.URL)
			t.Chdir(dir)
			t.Setenv("DTRACK_API_KEY", "synthetic-key")
			flag := "--evidence="
			if kind == "existing" {
				flag = "--evidence=record.json"
				os.WriteFile("record.json", []byte("original"), 0600)
			}
			r := rio(t, dir, "deliver", flag, "--json")
			requireExit(t, r, ExitUsage)
			if calls != 0 {
				t.Fatal("request after invalid evidence output", calls)
			}
			if kind == "existing" {
				m := decode(t, []byte(r.stdout))
				if m["evidence"].(map[string]any)["outputMayExist"] != true {
					t.Fatal("existing output presence misreported", m)
				}
			}
		})
	}
}
