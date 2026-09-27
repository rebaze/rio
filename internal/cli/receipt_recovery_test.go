package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/receipt"
)

func TestReceiptRecoveryRetainsCommittedResultsOffline(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"11111111-1111-4111-8111-111111111111"}`)
	}))
	defer srv.Close()
	dir := pipelineFixture(t, srv.URL)
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "synthetic")
	_, prior, path := rootReceipt(t)
	raw, _ := os.ReadFile(path)
	runDir := filepath.Dir(path)
	entries, _ := filepath.Glob(filepath.Join(runDir, ".internal", "checkpoint-*.json"))
	sort.Strings(entries)
	// Remove only the final completion checkpoint, simulating interruption after
	// committed adapter facts but before invocation completion publication.
	os.Remove(entries[len(entries)-1])
	os.Remove("api.cdx.json")
	os.Remove("worker.cdx.json")
	os.Remove("rio.yaml")
	recovered, e := recoverInvocation(runDir)
	if e != nil {
		t.Fatal(e)
	}
	if recovered.Run.ID != prior.Run.ID || recovered.Run.Outcome != "incomplete" || recovered.Run.FinishedAt != "" || len(recovered.Deliveries) != 2 || recovered.Deliveries[0].State != "accepted" || len(recovered.Deliveries[0].Responses) != 1 || calls.Load() != 2 {
		t.Fatalf("%#v calls=%d", recovered, calls.Load())
	}
	unchanged, _ := os.ReadFile(path)
	if !bytes.Equal(raw, unchanged) {
		t.Fatal("prior receipt replaced")
	}
	if _, e = receipt.Marshal(recovered); e != nil {
		t.Fatal(e)
	}
}

type stopAfterResponse struct {
	delivery.Target
	marker string
}

func (t stopAfterResponse) Submit(ctx context.Context, p []delivery.Payload) (delivery.Submission, error) {
	sub, e := t.Target.Submit(ctx, p)
	if e != nil {
		return sub, e
	}
	if e = os.WriteFile(t.marker, []byte("received"), 0600); e != nil {
		return sub, e
	}
	select {}
}
func TestReceiptRecoveryAfterHardKillNeverReplays(t *testing.T) {
	if marker := os.Getenv("RIO_106_KILL_MARKER"); marker != "" {
		original := deliveryBuild
		deliveryBuild = func(p delivery.Provider, d delivery.Description) (delivery.Target, error) {
			target, e := original(p, d)
			if e != nil {
				return nil, e
			}
			return stopAfterResponse{target, marker}, nil
		}
		Main(nil, io.Discard, os.Stderr)
		os.Exit(8)
	}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"11111111-1111-4111-8111-111111111111"}`)
	}))
	defer srv.Close()
	dir := pipelineFixture(t, srv.URL)
	marker := filepath.Join(dir, "received")
	child := exec.Command(os.Args[0], "-test.run=^TestReceiptRecoveryAfterHardKillNeverReplays$")
	child.Dir = dir
	child.Env = append(os.Environ(), "RIO_106_KILL_MARKER="+marker, "DTRACK_API_KEY=synthetic")
	var stderr bytes.Buffer
	child.Stderr = &stderr
	if e := child.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if child.ProcessState == nil {
			child.Process.Kill()
			child.Wait()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, e := os.Stat(marker); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not reach response", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e := child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if e := child.Wait(); e == nil {
		t.Fatal("child was not killed")
	}
	dirs, _ := filepath.Glob(filepath.Join(dir, "target", "rio", "runs", "run-*"))
	if len(dirs) != 1 {
		t.Fatal(dirs)
	}
	r, e := recoverInvocation(dirs[0])
	if e != nil {
		t.Fatal(e)
	}
	if r.Run.Outcome != "incomplete" || r.Run.FinishedAt != "" || calls.Load() != 1 || len(r.Deliveries) != 2 || r.Deliveries[0].State != "unknown" || !r.Deliveries[0].RequestMayHaveOccurred || len(r.Deliveries[0].Responses) != 0 || r.Deliveries[1].State != "evidence-gap" {
		t.Fatalf("fabricated/replayed: %#v calls=%d", r, calls.Load())
	}
	if _, e = os.Stat(filepath.Join(dirs[0], "record.json")); !os.IsNotExist(e) {
		t.Fatal("fabricated completed receipt")
	}
	if _, e = os.Stat(filepath.Join(dirs[0], "record.json.lock")); e != nil {
		t.Fatal("removed crash lock")
	}
}

func TestReceiptRecoveryDoesNotDiscardCheckpointedAcknowledgment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"11111111-1111-4111-8111-111111111111"}`)
	}))
	defer srv.Close()
	dir := pipelineFixture(t, srv.URL)
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "synthetic")
	_, _, path := rootReceipt(t)
	runDir := filepath.Dir(path)
	checkpoints, _ := filepath.Glob(filepath.Join(runDir, ".internal", "checkpoint-*.json"))
	sort.Strings(checkpoints)
	os.Remove(checkpoints[len(checkpoints)-1])
	mappings, _ := os.ReadFile(filepath.Join(runDir, ".internal", "attempts.json"))
	var attempts []recoveryAttempt
	if e := json.Unmarshal(mappings, &attempts); e != nil {
		t.Fatal(e)
	}
	// The independently committed receipt checkpoint is still evidence when the
	// journal response file is unavailable; recovery must not erase its token.
	os.Remove(filepath.Join(attempts[0].Journal, "00000000000000000001.json"))
	d, e := recoverInvocation(runDir)
	if e != nil {
		t.Fatal(e)
	}
	if d.Deliveries[0].State != "accepted" || len(d.Deliveries[0].Responses) != 1 || len(d.Deliveries[0].Responses[0].References) != 1 {
		t.Fatalf("checkpointed response lost: %#v", d.Deliveries[0])
	}
}

func TestPipelineReceiptPersistenceFailureAfterRequests(t *testing.T) {
	var calls atomic.Int32
	dir := pipelineFixture(t, "")
	output := filepath.Join(dir, "receipt.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		os.WriteFile(output, []byte("competing owner"), 0600)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"11111111-1111-4111-8111-111111111111"}`)
	}))
	defer srv.Close()
	f, e := os.OpenFile(filepath.Join(dir, "rio.yaml"), os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Fprintf(f, "delivery:\n  targets:\n    security:\n      type: dependency-track\n      url: %s\n      allowHTTP: true\n", srv.URL)
	f.Close()
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "synthetic")
	var out, stderr bytes.Buffer
	code := Main([]string{"--receipt", output, "--json"}, &out, &stderr)
	var result struct {
		Outcome      string `json:"outcome"`
		RunDirectory string `json:"runDirectory"`
	}
	if e = json.Unmarshal(out.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if code != ExitInternal || result.Outcome != "failed" || calls.Load() != 2 || !strings.Contains(stderr.String(), "without resubmitting") {
		t.Fatalf("code=%d calls=%d out=%s err=%s", code, calls.Load(), out.String(), stderr.String())
	}
	raw, _ := os.ReadFile(output)
	if string(raw) != "competing owner" {
		t.Fatal("replaced competing output")
	}
	d, e := recoverInvocation(result.RunDirectory)
	if e != nil {
		t.Fatal(e)
	}
	if len(d.Deliveries) != 2 || d.Deliveries[0].State != "accepted" || d.Run.Outcome != "failed" || calls.Load() != 2 {
		t.Fatalf("recovery %#v", d)
	}
}
