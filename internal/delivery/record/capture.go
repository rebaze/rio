package record

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rebaze/rio/internal/delivery"
)

const MaxDirectoryEntries = 20000

// Capture retains the very buffers replayed under one journal lock.
type Capture struct {
	Snapshot  Snapshot
	RawEvents [][]byte
}

// CaptureRead locks once, bounds each read by the remaining budget, and releases
// before returning. A cleanup failure takes precedence over an invalid source.
func CaptureRead(path string, maxBytes int64) (Capture, error) {
	return captureRead(path, maxBytes, nil)
}
func captureRead(path string, maxBytes int64, setup func(*Writer)) (c Capture, err error) {
	w, err := acquire(path)
	if err != nil {
		return c, err
	}
	defer func() {
		if e := w.Close(); e != nil {
			err = e
		}
	}()
	if setup != nil {
		setup(w)
	}
	return w.capture(false, maxBytes, true)
}
func emptySnapshot() Snapshot {
	return Snapshot{Events: []Event{}, References: []delivery.Reference{}, Observations: []delivery.Observation{}, OrphanTemps: []string{}}
}

// DecodeEvents replays committed records without consulting any external path.
func DecodeEvents(rawEvents [][]byte) (Snapshot, error) {
	s := emptySnapshot()
	if len(rawEvents) == 0 || len(rawEvents) > MaxEvents {
		return s, invalid()
	}
	h := sha256.New()
	for _, b := range rawEvents {
		if e := replayRaw(&s, b); e != nil {
			return s, e
		}
		h.Write(b)
	}
	s.SHA256 = hex.EncodeToString(h.Sum(nil))
	return s, nil
}
func replayRaw(s *Snapshot, b []byte) error {
	if int64(len(b)) > EventLimit {
		return delivery.Fail("size_limit", "maximum event bytes")
	}
	var e Event
	if delivery.DecodeJSON(b, &e, true) != nil {
		return invalid()
	}
	return addEvent(s, e)
}
func (w *Writer) capture(empty bool, budget int64, retain bool) (c Capture, err error) {
	c = Capture{Snapshot: emptySnapshot(), RawEvents: [][]byte{}}
	if w.closed {
		return c, delivery.Fail("record_closed", "writer")
	}
	if budget < 0 {
		return c, delivery.Fail("size_limit", "journal capture budget")
	}
	st, e := os.Lstat(w.path)
	if e != nil || !st.IsDir() {
		return c, invalid()
	}
	f, e := os.Open(w.path)
	if e != nil {
		return c, invalid()
	}
	defer func() {
		if e := f.Close(); e != nil {
			err = delivery.Fail("persistence_failed", "close journal directory")
		}
	}()
	names := []string{}
	entries := 0
	for {
		batch, e := f.ReadDir(128)
		for _, ent := range batch {
			entries++
			if entries > MaxDirectoryEntries {
				return c, delivery.Fail("size_limit", "maximum journal directory entries")
			}
			n := ent.Name()
			if strings.HasPrefix(n, ".event-") && strings.HasSuffix(n, ".tmp") {
				c.Snapshot.OrphanTemps = append(c.Snapshot.OrphanTemps, n)
				continue
			}
			if ent.Type()&os.ModeSymlink != 0 || !ent.Type().IsRegular() || len(n) != 25 || !strings.HasSuffix(n, ".json") {
				return c, invalid()
			}
			names = append(names, n)
			if len(names) > MaxEvents {
				return c, delivery.Fail("size_limit", "maximum journal events")
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return c, invalid()
		}
	}
	if len(names) == 0 && !empty {
		return c, invalid()
	}
	sort.Strings(names)
	sort.Strings(c.Snapshot.OrphanTemps)
	h := sha256.New()
	for n, name := range names {
		if name != eventName(n) {
			return c, invalid()
		}
		limit := min(EventLimit, budget)
		b, e := delivery.ReadBounded(filepath.Join(w.path, name), limit)
		if e != nil {
			return c, e
		}
		budget -= int64(len(b))
		if e = replayRaw(&c.Snapshot, b); e != nil {
			return c, e
		}
		h.Write(b)
		if retain {
			c.RawEvents = append(c.RawEvents, b)
		}
	}
	c.Snapshot.SHA256 = hex.EncodeToString(h.Sum(nil))
	return c, nil
}
