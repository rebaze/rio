package record

import (
	"bytes"
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIntentGolden(t *testing.T) {
	p := filepath.Join(t.TempDir(), "record")
	w, e := create(p, intent(), func(w *Writer) {
		w.clock = func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) }
		w.random = bytes.NewReader(make([]byte, 16))
	})
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	got, e := os.ReadFile(filepath.Join(p, eventName(0)))
	if e != nil {
		t.Fatal(e)
	}
	gold := "testdata/intent.json"
	if os.Getenv("RIO_UPDATE_GOLDEN") == "1" {
		os.MkdirAll("testdata", 0755)
		os.WriteFile(gold, got, 0600)
	}
	want, e := os.ReadFile(gold)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("event differs from golden")
	}
}
func TestIntentPersistenceFailure(t *testing.T) {
	for _, point := range []string{"write", "sync", "close", "rename", "directory-sync"} {
		t.Run(point, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "record")
			w, e := create(p, intent(), func(w *Writer) {
				w.fail = func(s string) error {
					if s == point {
						return delivery.Fail("persistence_failed", "injected")
					}
					return nil
				}
			})
			if e == nil || w != nil {
				t.Fatal("intent failure returned writer")
			}
		})
	}
}
func TestEventSizeLimit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "record")
	w, e := Create(p, intent())
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	var sub delivery.Submission
	json.Unmarshal(submission(), &sub)
	sub.References = []delivery.Reference{{Kind: "object", Value: string(bytes.Repeat([]byte("x"), int(EventLimit)))}}
	b, _ := json.Marshal(sub)
	if e = w.Append("submission", b); e == nil {
		t.Fatal("oversized event committed")
	}
	s, e := w.Snapshot()
	if e != nil || len(s.Events) != 1 {
		t.Fatal(s, e)
	}
}
