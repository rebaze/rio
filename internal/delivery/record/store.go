package record

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/rebaze/rio/internal/delivery"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Writer struct {
	path, lock string
	closed     bool
	clock      func() time.Time
	random     io.Reader
	fail       func(string) error
}

func eventName(n int) string { return fmt.Sprintf("%020d.json", n) }
func acquire(path string) (*Writer, error) {
	abs, e := filepath.Abs(path)
	if e != nil {
		return nil, delivery.Fail("invalid_record_path", "record")
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(abs))
	if e != nil {
		return nil, delivery.Fail("invalid_record_path", "existing parent required")
	}
	p := filepath.Join(parent, filepath.Base(abs))
	if filepath.Base(abs) == "." || p == parent {
		return nil, delivery.Fail("invalid_record_path", "record")
	}
	if st, e := os.Lstat(p); e == nil && st.Mode()&os.ModeSymlink != 0 {
		return nil, delivery.Fail("invalid_record_path", "symlink record")
	}
	lock := p + ".lock"
	if e = os.Mkdir(lock, 0700); e != nil {
		if os.IsExist(e) {
			return nil, delivery.Fail("record_busy", "record lock exists; never removed automatically")
		}
		return nil, delivery.Fail("persistence_failed", "create lock")
	}
	return &Writer{path: p, lock: lock, clock: time.Now, random: rand.Reader}, nil
}
func Create(path string, i Intent) (*Writer, error) { return create(path, i, nil) }
func create(path string, i Intent, setup func(*Writer)) (*Writer, error) {
	if validateIntent(i) != nil {
		return nil, invalid()
	}
	w, e := acquire(path)
	if e != nil {
		return nil, e
	}
	if setup != nil {
		setup(w)
	}
	if _, e = os.Lstat(w.path); e == nil {
		w.Close()
		return nil, delivery.Fail("record_exists", "new journal directory required")
	} else if !os.IsNotExist(e) {
		w.Close()
		return nil, delivery.Fail("invalid_record_path", "record")
	}
	if e = os.Mkdir(w.path, 0700); e != nil {
		w.Close()
		return nil, delivery.Fail("persistence_failed", "create journal")
	}
	b, _ := json.Marshal(i)
	if e = w.Append("intent", b); e != nil {
		w.Close()
		return nil, e
	}
	if _, e = w.Snapshot(); e != nil {
		w.Close()
		return nil, e
	}
	return w, nil
}
func Open(path string) (*Writer, error) {
	w, e := acquire(path)
	if e != nil {
		return nil, e
	}
	if _, e = w.Snapshot(); e != nil {
		w.Close()
		return nil, e
	}
	return w, nil
}
func Read(path string) (Snapshot, error) {
	w, e := Open(path)
	if e != nil {
		return Snapshot{}, e
	}
	defer w.Close()
	return w.Snapshot()
}
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if os.Remove(w.lock) != nil {
		return delivery.Fail("persistence_failed", "remove owned lock")
	}
	return nil
}
func (w *Writer) Snapshot() (Snapshot, error) { return w.read(false) }
func (w *Writer) read(empty bool) (Snapshot, error) {
	s := Snapshot{Events: []Event{}, References: []delivery.Reference{}, Observations: []delivery.Observation{}, OrphanTemps: []string{}}
	if w.closed {
		return s, delivery.Fail("record_closed", "writer")
	}
	entries, e := os.ReadDir(w.path)
	if e != nil {
		return s, invalid()
	}
	names := []string{}
	for _, ent := range entries {
		n := ent.Name()
		if strings.HasPrefix(n, ".event-") && strings.HasSuffix(n, ".tmp") {
			s.OrphanTemps = append(s.OrphanTemps, n)
			continue
		}
		if ent.Type()&os.ModeSymlink != 0 || !ent.Type().IsRegular() || len(n) != 25 || !strings.HasSuffix(n, ".json") {
			return s, invalid()
		}
		names = append(names, n)
	}
	if len(names) > MaxEvents || len(names) == 0 && !empty {
		return s, invalid()
	}
	sort.Strings(names)
	h := sha256.New()
	for n, name := range names {
		if name != eventName(n) {
			return s, invalid()
		}
		b, e := delivery.ReadBounded(filepath.Join(w.path, name), EventLimit)
		if e != nil {
			return s, e
		}
		var event Event
		if delivery.DecodeJSON(b, &event, true) != nil {
			return s, invalid()
		}
		if e = addEvent(&s, event); e != nil {
			return s, e
		}
		h.Write(b)
	}
	s.SHA256 = hex.EncodeToString(h.Sum(nil))
	return s, nil
}
func (w *Writer) failure(point string) error {
	if w.fail != nil {
		return w.fail(point)
	}
	return nil
}
func (w *Writer) Append(kind string, data json.RawMessage) error {
	s, e := w.read(kind == "intent")
	if e != nil {
		return e
	}
	if len(s.Events) >= MaxEvents {
		return delivery.Fail("size_limit", "maximum journal events")
	}
	id := ""
	if len(s.Events) == 0 {
		b := make([]byte, 16)
		if _, e = io.ReadFull(w.random, b); e != nil {
			return delivery.Fail("persistence_failed", "attempt identity")
		}
		id = hex.EncodeToString(b)
	} else {
		id = s.Events[0].AttemptID
	}
	event := Event{1, len(s.Events), id, w.clock().UTC().Format(time.RFC3339Nano), kind, data}
	if e = addEvent(&s, event); e != nil {
		return e
	}
	b, e := json.MarshalIndent(event, "", "  ")
	if e != nil {
		return invalid()
	}
	b = append(b, '\n')
	if int64(len(b)) > EventLimit {
		return delivery.Fail("size_limit", "maximum event bytes")
	}
	f, e := os.CreateTemp(w.path, ".event-*.tmp")
	if e != nil {
		return delivery.Fail("persistence_failed", "create event")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	failed := func() error { f.Close(); return delivery.Fail("persistence_failed", "commit journal event") }
	if w.failure("write") != nil {
		return failed()
	}
	if _, e = f.Write(b); e != nil {
		return failed()
	}
	if w.failure("sync") != nil {
		return failed()
	}
	if e = f.Sync(); e != nil {
		return failed()
	}
	if w.failure("close") != nil {
		return failed()
	}
	if e = f.Close(); e != nil {
		return failed()
	}
	final := filepath.Join(w.path, eventName(event.Sequence))
	if _, e = os.Lstat(final); !os.IsNotExist(e) {
		return failed()
	}
	if w.failure("rename") != nil {
		return failed()
	}
	if e = os.Rename(tmp, final); e != nil {
		return failed()
	}
	if w.failure("directory-sync") != nil {
		return failed()
	}
	if e = syncDirectory(w.path); e != nil {
		return failed()
	}
	return nil
}
