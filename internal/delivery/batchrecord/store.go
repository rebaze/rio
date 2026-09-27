package batchrecord

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
)

type Paths struct{ Output, Index, Descriptor, Completion string }

func EvidencePaths(output string) Paths {
	return Paths{output, output + ".index.json", output + ".batch.json", output + ".batch-result.json"}
}
func (p Paths) all() []string { return []string{p.Output, p.Index, p.Descriptor, p.Completion} }

type Reservation struct {
	Paths  Paths
	locks  []string
	closed bool
	// Fault injection belongs to this package's store tests; never sourced from env.
	fail func(string) error
}

func persistence(field string) error { return delivery.Fail("persistence_failed", field) }
func absent(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return delivery.Fail("output_exists", "new evidence path required")
	} else if !os.IsNotExist(err) {
		return delivery.Fail("invalid_output", "evidence path")
	}
	return nil
}
func canonical(path string) (string, error) {
	if !ValidHint(path) {
		return "", delivery.Fail("invalid_output", "evidence path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", delivery.Fail("invalid_output", "evidence path")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", delivery.Fail("invalid_output", "existing parent directory required")
	}
	st, err := os.Stat(parent)
	if err != nil || !st.IsDir() {
		return "", delivery.Fail("invalid_output", "existing parent directory required")
	}
	return filepath.Join(parent, filepath.Base(abs)), nil
}
func samePath(a, b string) bool {
	if a == b {
		return true
	}
	aa, ea := os.Stat(a)
	bb, eb := os.Stat(b)
	return ea == nil && eb == nil && os.SameFile(aa, bb)
}
func inside(a, b string) bool {
	for {
		if samePath(a, b) {
			return true
		}
		parent := filepath.Dir(a)
		if parent == a {
			return false
		}
		a = parent
	}
}
func collide(a, b string) bool { return inside(a, b) || inside(b, a) }

// Reserve checks all final/source/lock namespaces before taking owned locks.
// It creates no sources and never removes pre-existing files or stale locks.
func Reserve(output, indexPath string, journals []string) (result *Reservation, err error) {
	out, err := canonical(output)
	if err != nil {
		return nil, err
	}
	r := &Reservation{Paths: EvidencePaths(out)}
	source, err := filepath.EvalSymlinks(indexPath)
	if err != nil {
		return nil, delivery.Fail("read_failed", "source index")
	}
	source, err = filepath.Abs(source)
	if err != nil {
		return nil, delivery.Fail("invalid_output", "source index")
	}
	for _, p := range r.Paths.all() {
		if err = absent(p); err != nil {
			return nil, err
		}
		for _, candidate := range []string{p, p + ".lock"} {
			if collide(candidate, source) {
				return nil, delivery.Fail("output_collision", "evidence overlaps source index")
			}
		}
		for _, journal := range journals {
			root, e := canonical(journal)
			if e != nil {
				return nil, e
			}
			// Materialize the journal's ordinary exclusive namespace to catch aliases
			// on case-insensitive filesystems even when the journal does not yet exist.
			e = record.WithJournalLock(root, func(root, lock string) error {
				for _, candidate := range []string{p, p + ".lock"} {
					for _, name := range []string{root, lock} {
						if collide(candidate, name) {
							return delivery.Fail("output_collision", "evidence overlaps journal")
						}
					}
				}
				return nil
			})
			if e != nil {
				return nil, e
			}
		}
	}
	defer func() {
		if result == nil {
			if e := r.Close(); e != nil {
				err = e
			}
		}
	}()
	paths := r.Paths.all()
	sort.Strings(paths)
	for _, p := range paths {
		lock := p + ".lock"
		if err = os.Mkdir(lock, 0700); err != nil {
			if os.IsExist(err) {
				return nil, delivery.Fail("record_busy", "evidence lock exists; never removed automatically")
			}
			return nil, persistence("create evidence lock")
		}
		r.locks = append(r.locks, lock)
		if err = absent(p); err != nil {
			return nil, err
		}
	}
	return r, nil
}
func (r *Reservation) Close() error {
	if r == nil || r.closed {
		return nil
	}
	r.closed = true
	var err error
	for i := len(r.locks) - 1; i >= 0; i-- {
		if e := os.Remove(r.locks[i]); e != nil {
			err = persistence("remove owned evidence lock")
		}
	}
	return err
}
func (r *Reservation) owns(path string) bool {
	if r == nil || r.closed {
		return false
	}
	for _, p := range r.Paths.all() {
		if p == path {
			return true
		}
	}
	return false
}

// Publish uses a synced temporary and hard-link no-replace commit. The boolean
// remains true after a post-publication failure, so callers never promise absence.
func (r *Reservation) Publish(path string, raw []byte, limit int64, validate func([]byte) error) (mayExist bool, err error) {
	if !r.owns(path) {
		return false, delivery.Fail("invalid_output", "unreserved evidence path")
	}
	if int64(len(raw)) > limit {
		return false, delivery.Fail("size_limit", "evidence output bytes")
	}
	if validate != nil {
		if err = validate(raw); err != nil {
			return false, err
		}
	}
	if err = absent(path); err != nil {
		return true, err
	}
	fail := func(point string) bool { return r.fail != nil && r.fail(point) != nil }
	f, e := os.CreateTemp(filepath.Dir(path), ".rio-batch-*.tmp")
	if e != nil {
		return false, persistence("create evidence temporary")
	}
	tmp := f.Name()
	open := true
	defer func() {
		if open {
			if e := f.Close(); e != nil {
				err = persistence("close evidence temporary")
			}
		}
		if e := os.Remove(tmp); e != nil && !os.IsNotExist(e) {
			err = persistence("remove owned evidence temporary")
		}
	}()
	if fail("write") {
		return false, persistence("write evidence")
	}
	if _, e = f.Write(raw); e != nil {
		return false, persistence("write evidence")
	}
	if fail("sync") {
		return false, persistence("sync evidence")
	}
	if e = f.Sync(); e != nil {
		return false, persistence("sync evidence")
	}
	e = f.Close()
	open = false
	if e != nil {
		return false, persistence("close evidence temporary")
	}
	if fail("publish") {
		return false, persistence("publish evidence")
	}
	if e = os.Link(tmp, path); e != nil {
		_, statErr := os.Lstat(path)
		return os.IsExist(e) || statErr == nil, persistence("publish absent evidence")
	}
	mayExist = true
	if fail("directory-sync") {
		return true, persistence("sync evidence directory")
	}
	if e = syncDirectory(filepath.Dir(path)); e != nil {
		return true, persistence("sync evidence directory")
	}
	if fail("read-back") {
		return true, persistence("read back evidence")
	}
	saved, e := delivery.ReadBounded(path, limit)
	if e != nil || !bytes.Equal(saved, raw) {
		return true, persistence("read back evidence")
	}
	if validate != nil {
		if e = validate(saved); e != nil {
			return true, persistence("validate saved evidence")
		}
	}
	return true, nil
}
func (r *Reservation) PublishSources(indexRaw, batchRaw []byte) error {
	d, err := ParseDescriptor(batchRaw)
	if err != nil {
		return err
	}
	if d.Index.PathHint != r.Paths.Index || d.CompletionPathHint != r.Paths.Completion {
		return invalid()
	}
	if err = ValidateIndex(d, indexRaw); err != nil {
		return err
	}
	// A complete descriptor is never published ahead of its recoverable index.
	if _, err = r.Publish(r.Paths.Index, indexRaw, delivery.IndexLimit, func(raw []byte) error { return ValidateIndex(d, raw) }); err != nil {
		return err
	}
	_, err = r.Publish(r.Paths.Descriptor, batchRaw, SourceLimit, func(raw []byte) error { _, err := ParseDescriptor(raw); return err })
	return err
}
func (r *Reservation) PublishCompletion(c Completion, d Descriptor, batchRaw []byte) error {
	raw, err := MarshalCompletion(c, d, batchRaw)
	if err != nil {
		return err
	}
	_, err = r.Publish(r.Paths.Completion, raw, SourceLimit, func(raw []byte) error { _, err := ParseCompletion(raw, d, batchRaw); return err })
	return err
}

// ResolveHint resolves a selected descriptor's relative recovery path. It never
// searches directories and is not used when inspecting a portable record.
func ResolveHint(descriptorPath, hint string) (string, error) {
	if !ValidHint(hint) {
		return "", invalid()
	}
	if filepath.IsAbs(hint) {
		return hint, nil
	}
	return filepath.Join(filepath.Dir(descriptorPath), filepath.FromSlash(hint)), nil
}
