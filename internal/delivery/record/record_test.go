package record

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/rebaze/rio/internal/delivery"
	"os"
	"path/filepath"
	"strings"
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

func TestJournalRejectsContradictoryEvidence(t *testing.T) {
	for _, kind := range []string{"payload-output", "payload-source", "identity-digest", "empty-ack"} {
		t.Run(kind, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "record")
			i := intent()
			switch kind {
			case "payload-output":
				i.Payloads[0].SHA256 = delivery.Digest([]byte("other"))
			case "payload-source":
				i.Payloads[0].SourceSHA256 = delivery.Digest([]byte("other"))
			case "identity-digest":
				i.Payloads[0].Size = 0
			}
			w, e := Create(p, i)
			if kind != "empty-ack" {
				if e == nil {
					w.Close()
					t.Fatal("inconsistent intent accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer w.Close()
			b, _ := json.Marshal(delivery.Submission{Disposition: "accepted", References: []delivery.Reference{}, Observations: []delivery.Observation{}})
			if e = w.Append("submission", b); e == nil {
				t.Fatal("unsupported acceptance accepted")
			}
		})
	}
}

func TestOversizedIntentWritesNoJournal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "record")
	i := intent()
	i.Binding = string(bytes.Repeat([]byte("x"), int(EventLimit)))
	if w, e := Create(p, i); e == nil {
		w.Close()
		t.Fatal("oversized intent accepted")
	}
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("oversized intent left persistent journal")
	}
}
func TestReadReportsLockCleanupFailure(t *testing.T) {
	p := filepath.Join(t.TempDir(), "record")
	w, e := Create(p, intent())
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(w.lock, "obstruction"), []byte("x"), 0600)
	if _, e = readLocked(w); e == nil {
		t.Fatal("lock cleanup failure hidden")
	}
}

func TestNullIntentFieldsWriteNoJournal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "record")
	i := intent()
	i.Destination.CredentialRefs = nil
	if w, e := Create(p, i); e == nil {
		w.Close()
		t.Fatal("null required array accepted")
	}
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("invalid intent left journal")
	}
}

func TestCheckIntentAppendReplayCompleteByteBoundary(t *testing.T) {
	setup := func(w *Writer) {
		w.clock = func() time.Time { return time.Date(2000, 1, 1, 0, 0, 0, 123456789, time.UTC) }
		w.random = bytes.NewReader(make([]byte, 16))
	}
	seed := intent()
	dir := filepath.Join(t.TempDir(), "seed")
	w, e := create(dir, seed, setup)
	if e != nil {
		t.Fatal(e)
	}
	w.Close()
	raw, e := os.ReadFile(filepath.Join(dir, eventName(0)))
	if e != nil {
		t.Fatal(e)
	}
	for _, extra := range []int{0, 1} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			i := intent()
			i.Binding = strings.Repeat("x", int(EventLimit)-len(raw)+len(seed.Binding)+extra)
			path := filepath.Join(t.TempDir(), "boundary")
			preflightErr := CheckIntent(i)
			w, e := create(path, i, setup)
			if extra == 1 {
				if preflightErr == nil || e == nil {
					t.Fatal("overflow disagreed with complete envelope limit")
				}
				if _, e = os.Stat(path); !os.IsNotExist(e) {
					t.Fatal("overflow created journal")
				}
				return
			}
			if preflightErr != nil || e != nil {
				t.Fatal(preflightErr, e)
			}
			w.Close()
			committed, e := os.ReadFile(filepath.Join(path, eventName(0)))
			if e != nil || int64(len(committed)) != EventLimit {
				t.Fatal(len(committed), e)
			}
			if _, e = DecodeEvents([][]byte{committed}); e != nil {
				t.Fatal("exact complete envelope failed replay", e)
			}
		})
	}
}
