package record

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/rebaze/rio/internal/delivery"
	"io"
	"os"
	"path/filepath"
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

// Reservation owns a journal's exclusive sibling lock without creating an intent.
type Reservation struct{ writer *Writer }

func Reserve(path string) (*Reservation, error) { return reserve(path, nil) }
func reserve(path string, setup func(*Writer)) (r *Reservation, err error) {
	w, e := acquire(path)
	if e != nil {
		return nil, e
	}
	defer func() {
		if r == nil {
			if e := w.Close(); e != nil {
				err = e
			}
		}
	}()
	if setup != nil {
		setup(w)
	}
	if _, e := os.Lstat(w.path); e == nil {
		return nil, delivery.Fail("record_exists", "new journal directory required")
	} else if !os.IsNotExist(e) {
		return nil, delivery.Fail("invalid_record_path", "record")
	}
	return &Reservation{writer: w}, nil
}
func (r *Reservation) Close() error {
	if r.writer == nil {
		return nil
	}
	w := r.writer
	r.writer = nil
	return w.Close()
}
func (r *Reservation) Path() string {
	if r.writer == nil {
		return ""
	}
	return r.writer.path
}
func Create(path string, i Intent) (*Writer, error) { return create(path, i, nil) }
func create(path string, i Intent, setup func(*Writer)) (result *Writer, err error) {
	if e := checkIntent(i); e != nil {
		return nil, e
	}
	r, e := reserve(path, setup)
	if e != nil {
		return nil, e
	}
	return r.Create(i)
}

// CheckIntent validates the complete eventual event envelope without filesystem effects.
// Create repeats this check under its reservation before publication.
func CheckIntent(i Intent) error { return checkIntent(i) }

func checkIntent(i Intent) error {
	if validateIntent(i) != nil {
		return invalid()
	}
	// Bound the exact worst-length event envelope before persistent directory creation.
	data, err := json.Marshal(i)
	if err != nil {
		return invalid()
	}
	var checked Intent
	if delivery.DecodeJSON(data, &checked, true) != nil {
		return invalid()
	}
	preview := Event{1, 0, strings.Repeat("0", 32), "2000-01-01T00:00:00.123456789Z", "intent", data}
	encoded, err := json.MarshalIndent(preview, "", "  ")
	if err != nil {
		return invalid()
	}
	if int64(len(encoded)+1) > EventLimit {
		return delivery.Fail("size_limit", "maximum event bytes")
	}
	return nil
}
func (r *Reservation) Create(i Intent) (result *Writer, err error) {
	if r.writer == nil {
		return nil, delivery.Fail("record_closed", "reservation")
	}
	w := r.writer
	r.writer = nil // transfer exactly once; former owner can no longer release this lock
	var e error
	defer func() {
		if result == nil {
			if closeErr := w.Close(); closeErr != nil {
				err = closeErr
			}
		}
	}()
	if e = checkIntent(i); e != nil {
		return nil, e
	}
	if _, e = os.Lstat(w.path); e == nil {
		return nil, delivery.Fail("record_exists", "new journal directory required")
	} else if !os.IsNotExist(e) {
		return nil, delivery.Fail("invalid_record_path", "record")
	}
	if e = os.Mkdir(w.path, 0700); e != nil {
		return nil, delivery.Fail("persistence_failed", "create journal")
	}
	b, _ := json.Marshal(i)
	if e = w.Append("intent", b); e != nil {
		return nil, e
	}
	if _, e = w.Snapshot(); e != nil {
		return nil, e
	}
	return w, nil
}
func Open(path string) (*Writer, error) { return open(path, nil) }
func open(path string, setup func(*Writer)) (result *Writer, err error) {
	w, e := acquire(path)
	if e != nil {
		return nil, e
	}
	defer func() {
		if result == nil {
			if closeErr := w.Close(); closeErr != nil {
				err = closeErr
			}
		}
	}()
	if setup != nil {
		setup(w)
	}
	if _, e = w.Snapshot(); e != nil {
		return nil, e
	}
	return w, nil
}
func Read(path string) (Snapshot, error) {
	w, e := Open(path)
	if e != nil {
		return Snapshot{}, e
	}
	return readLocked(w)
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
	c, err := w.capture(empty, EventLimit*MaxEvents, false)
	return c.Snapshot, err
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

func readLocked(w *Writer) (s Snapshot, err error) {
	defer func() {
		if e := w.Close(); e != nil {
			err = e
		}
	}()
	return w.Snapshot()
}

// WithJournalLock runs a metadata check under the same canonical sibling lock as
// capture and writers, without reading any journal event. Cleanup errors override
// a check failure. The callback must not retain ownership after it returns.
func WithJournalLock(path string, check func(canonicalPath, lockPath string) error) (err error) {
	w, err := acquire(path)
	if err != nil {
		return err
	}
	defer func() {
		if e := w.Close(); e != nil {
			err = e
		}
	}()
	return check(w.path, w.lock)
}
