package runner

import (
	"context"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
)

type crashAfterHTTP struct{ url string }

func (c crashAfterHTTP) Submit(ctx context.Context, ps []delivery.Payload) (delivery.Submission, error) {
	reader := ps[0].Open()
	defer reader.Close()
	req, e := http.NewRequestWithContext(ctx, "POST", c.url, reader)
	if e != nil {
		os.Exit(7)
	}
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		os.Exit(8)
	}
	b, e := io.ReadAll(resp.Body)
	resp.Body.Close()
	if e != nil || resp.StatusCode != 200 || string(b) != "accepted" {
		os.Exit(9)
	}
	os.Exit(0)
	return delivery.Submission{}, nil
}
func TestCrashAfterAcknowledgmentBeforePersistence(t *testing.T) {
	if endpoint := os.Getenv("RIO_CRASH_HTTP"); endpoint != "" {
		path := os.Getenv("RIO_CRASH_RECORD")
		p := prepared(t, path, false)
		p.Target = crashAfterHTTP{endpoint}
		Submit(context.Background(), p, path)
		t.Fatal("child did not terminate")
	}
	var requests atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "accepted")
	}))
	defer s.Close()
	p := filepath.Join(t.TempDir(), "record")
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashAfterAcknowledgmentBeforePersistence$")
	cmd.Env = append(os.Environ(), "RIO_CRASH_HTTP="+s.URL, "RIO_CRASH_RECORD="+p)
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatal(e, string(b))
	}
	if requests.Load() != 1 {
		t.Fatal("no real request")
	}
	if _, e := record.Read(p); e == nil {
		t.Fatal("crash lock lost")
	}
	os.Remove(p + ".lock")
	snapshot, e := record.Read(p)
	if e != nil || snapshot.Disposition != "unknown" || len(snapshot.Events) != 1 {
		t.Fatal(snapshot, e)
	}
	again := prepared(t, p, false)
	result, e := Submit(context.Background(), again, p)
	if e == nil || result.ExitCode != 2 || requests.Load() != 1 || again.Target.(*fakeTarget).calls != 0 {
		t.Fatal("reused journal after crash", result, e)
	}
}
