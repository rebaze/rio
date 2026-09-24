package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/rebaze/rio/internal/delivery"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func captureFixture(t *testing.T) (string, [][]byte) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "attempt")
	w, e := Create(p, intent())
	if e != nil {
		t.Fatal(e)
	}
	if e = w.Append("submission", submission()); e != nil {
		t.Fatal(e)
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	raw := [][]byte{}
	for n := 0; n < 2; n++ {
		b, e := os.ReadFile(filepath.Join(p, eventName(n)))
		if e != nil {
			t.Fatal(e)
		}
		b = append([]byte(" \n\t"), b...)
		if e = os.WriteFile(filepath.Join(p, eventName(n)), b, 0600); e != nil {
			t.Fatal(e)
		}
		raw = append(raw, b)
	}
	return p, raw
}
func TestCaptureExactBuffersAndOfflineReplay(t *testing.T) {
	p, raw := captureFixture(t)
	os.WriteFile(filepath.Join(p, ".event-orphan.tmp"), []byte("secret temporary data"), 0600)
	c, e := CaptureRead(p, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(c.RawEvents, raw) || c.Snapshot.SHA256 != delivery.Digest(bytes.Join(raw, nil)) || len(c.Snapshot.OrphanTemps) != 1 {
		t.Fatal("capture lost raw evidence or orphan count")
	}
	os.RemoveAll(p)
	s, e := DecodeEvents(c.RawEvents)
	if e != nil || s.SHA256 != c.Snapshot.SHA256 || len(s.OrphanTemps) != 0 || !reflect.DeepEqual(s.Events, c.Snapshot.Events) {
		t.Fatal("offline replay differs", e)
	}
}
func TestCaptureLockAndCutoff(t *testing.T) {
	p, _ := captureFixture(t)
	c, e := captureRead(p, 1<<20, func(w *Writer) {
		if competing, e := Open(p); e == nil {
			competing.Close()
			t.Error("competing writer acquired lock")
		}
	})
	if e != nil {
		t.Fatal(e)
	}
	w, e := Open(p)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(Reconciliation{Observation: delivery.Observation{Kind: "unavailable", Value: "unavailable", Origin: "local", Code: "query_failed", References: []delivery.Reference{}}, ConfigSHA256: intent().ConfigSHA256})
	if e = w.Append("reconciliation", b); e != nil {
		t.Fatal(e)
	}
	w.Close()
	if len(c.RawEvents) != 2 || len(c.Snapshot.Events) != 2 {
		t.Fatal("capture changed after append")
	}
}
func TestCaptureCleanupOverridesInvalidHistory(t *testing.T) {
	p := filepath.Join(t.TempDir(), "empty")
	os.Mkdir(p, 0700)
	_, e := captureRead(p, 1<<20, func(w *Writer) { os.WriteFile(filepath.Join(w.lock, "block"), nil, 0600) })
	if e == nil || e.Error() != "persistence_failed: remove owned lock" {
		t.Fatalf("cleanup hidden: %v", e)
	}
}
func TestCaptureRefusesSourcesAndLimits(t *testing.T) {
	p, raw := captureFixture(t)
	total := int64(len(raw[0]) + len(raw[1]))
	if _, e := CaptureRead(p, total); e != nil {
		t.Fatal(e)
	}
	if _, e := CaptureRead(p, total-1); e == nil {
		t.Fatal("aggregate overflow")
	}
	os.Mkdir(p+".lock", 0700)
	if _, e := CaptureRead(p, total); e == nil {
		t.Fatal("busy accepted")
	}
	os.Remove(p + ".lock")
	for _, kind := range []string{"missing", "empty", "gap", "corrupt", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			q, _ := captureFixture(t)
			switch kind {
			case "missing":
				os.RemoveAll(q)
			case "empty":
				os.RemoveAll(q)
				os.Mkdir(q, 0700)
			case "gap":
				os.Rename(filepath.Join(q, eventName(1)), filepath.Join(q, eventName(2)))
			case "corrupt":
				os.WriteFile(filepath.Join(q, eventName(1)), []byte("{}"), 0600)
			case "symlink":
				alias := q + "-alias"
				if e := os.Symlink(q, alias); e != nil {
					t.Skip(e)
				}
				q = alias
			}
			if _, e := CaptureRead(q, 1<<20); e == nil {
				t.Fatal("invalid source accepted")
			}
		})
	}
}
func TestDecodeEventsRefusals(t *testing.T) {
	_, raw := captureFixture(t)
	for _, kind := range []string{"empty", "duplicate-key", "case-alias", "version", "attempt", "gap", "duplicate-submission", "oversize", "too-many"} {
		t.Run(kind, func(t *testing.T) {
			r := append([][]byte{}, raw...)
			switch kind {
			case "empty":
				r = nil
			case "duplicate-key":
				r[0] = bytes.Replace(r[0], []byte(`"schemaVersion": 1`), []byte(`"schemaVersion": 1,"schemaVersion": 1`), 1)
			case "case-alias":
				r[0] = bytes.Replace(r[0], []byte(`"schemaVersion"`), []byte(`"SchemaVersion"`), 1)
			case "version":
				r[0] = bytes.Replace(r[0], []byte(`"schemaVersion": 1`), []byte(`"schemaVersion": 2`), 1)
			case "attempt":
				var ev Event
				json.Unmarshal(r[1], &ev)
				ev.AttemptID = "ffffffffffffffffffffffffffffffff"
				r[1], _ = json.Marshal(ev)
			case "gap":
				r[1] = bytes.Replace(r[1], []byte(`"sequence": 1`), []byte(`"sequence": 2`), 1)
			case "duplicate-submission":
				r = append(r, bytes.Replace(r[1], []byte(`"sequence": 1`), []byte(`"sequence": 2`), 1))
			case "oversize":
				r[0] = bytes.Repeat([]byte(" "), int(EventLimit)+1)
			case "too-many":
				r = make([][]byte, MaxEvents+1)
			}
			if _, e := DecodeEvents(r); e == nil {
				t.Fatal("invalid history accepted")
			}
		})
	}
}
func TestCaptureDirectoryEntryLimit(t *testing.T) {
	p, _ := captureFixture(t)
	for n := 0; n < 19998; n++ {
		f, e := os.CreateTemp(p, ".event-*.tmp")
		if e != nil {
			t.Fatal(e)
		}
		f.Close()
	}
	if _, e := CaptureRead(p, 1<<20); e != nil {
		t.Fatal("exact entry limit refused", e)
	}
	os.WriteFile(filepath.Join(p, ".event-extra.tmp"), nil, 0600)
	if _, e := CaptureRead(p, 1<<20); e == nil {
		t.Fatal("directory limit ignored")
	}
}

func TestDecodeEventsExactCountAndEventLimit(t *testing.T) {
	p, raw := captureFixture(t)
	raw[0] = append(raw[0], bytes.Repeat([]byte(" "), int(EventLimit)-len(raw[0]))...)
	if e := os.WriteFile(filepath.Join(p, eventName(0)), raw[0], 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := CaptureRead(p, EventLimit+int64(len(raw[1]))); e != nil {
		t.Fatal("exact event limit refused", e)
	}
	if e := os.WriteFile(filepath.Join(p, eventName(0)), append(raw[0], ' '), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := CaptureRead(p, EventLimit*2); e == nil {
		t.Fatal("event limit ignored")
	}
	var first Event
	json.Unmarshal(raw[0], &first)
	data, _ := json.Marshal(Reconciliation{Observation: delivery.Observation{Kind: "unavailable", Value: "unavailable", Origin: "local", Code: "query_failed", References: []delivery.Reference{}}, ConfigSHA256: intent().ConfigSHA256})
	for n := 2; n < MaxEvents; n++ {
		b, _ := json.Marshal(Event{SchemaVersion: 1, Sequence: n, AttemptID: first.AttemptID, ObservedAt: first.ObservedAt, Kind: "reconciliation", Data: data})
		raw = append(raw, b)
	}
	if s, e := DecodeEvents(raw); e != nil || len(s.Events) != 10000 {
		t.Fatal("exact event count refused", e)
	}
	raw = append(raw, raw[len(raw)-1])
	if _, e := DecodeEvents(raw); e == nil {
		t.Fatal("count limit ignored")
	}
}

func TestCaptureRemainingEventCapacityBeforeRead(t *testing.T) {
	p, _ := captureFixture(t)
	os.WriteFile(filepath.Join(p, eventName(1)), []byte("{}"), 0600)
	for _, capacity := range []int{0, 1} {
		c, e := CaptureRead(p, EventLimit*2, capacity)
		var safe *delivery.Error
		if !errors.As(e, &safe) || safe.Code != "size_limit" || len(c.RawEvents) != 0 || len(c.Snapshot.Events) != 0 {
			t.Fatalf("capacity=%d retained/replayed events before limit: %+v %v", capacity, c, e)
		}
	}
	os.Remove(filepath.Join(p, eventName(1)))
	if c, e := CaptureRead(p, EventLimit, 1); e != nil || len(c.RawEvents) != 1 {
		t.Fatal("exact remaining event capacity refused", e)
	}
}

func TestJournalMetadataLockDoesNotReadEvents(t *testing.T) {
	p := filepath.Join(t.TempDir(), "journal")
	os.Mkdir(p, 0700)
	os.WriteFile(filepath.Join(p, eventName(0)), []byte("corrupt and must not be read"), 0600)
	called := false
	e := WithJournalLock(p, func(path, lock string) error {
		called = true
		if _, e := os.Stat(lock); e != nil {
			t.Fatal(e)
		}
		if w, e := Open(path); e == nil {
			w.Close()
			t.Fatal("metadata check did not own shared journal lock")
		}
		return nil
	})
	if e != nil || !called {
		t.Fatal("metadata lock read/validated events", e)
	}
	if _, e = os.Stat(p + ".lock"); !os.IsNotExist(e) {
		t.Fatal("metadata lock not released")
	}
}
func TestJournalMetadataLockCleanupOverridesCheck(t *testing.T) {
	p := filepath.Join(t.TempDir(), "journal")
	e := WithJournalLock(p, func(_, lock string) error {
		os.WriteFile(filepath.Join(lock, "obstruction"), nil, 0600)
		return delivery.Fail("invalid_record", "injected")
	})
	var safe *delivery.Error
	if !errors.As(e, &safe) || safe.Code != "persistence_failed" {
		t.Fatal("metadata cleanup failure hidden", e)
	}
}
