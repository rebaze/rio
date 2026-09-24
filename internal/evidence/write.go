package evidence

import (
	"bytes"
	"os"
	"path/filepath"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
)

type Output struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type Publication struct {
	Output         *Output `json:"output,omitempty"`
	OutputMayExist bool    `json:"outputMayExist"`
}

// Publish commits a new regular file. A hard-link publication refuses even an
// uncooperative creator racing the sibling lock; it never replaces an entry.
func Publish(path, indexPath string, journalPaths []string, raw []byte, validate Validator, retryPolicy ...RetryValidator) (Publication, error) {
	return publish(path, indexPath, journalPaths, raw, validate, retryPolicy, nil)
}
func publish(path, indexPath string, journalPaths []string, raw []byte, validate Validator, retryPolicy []RetryValidator, fail func(string) error) (result Publication, err error) {
	if _, err = Parse(raw, validate, retryPolicy...); err != nil {
		return result, err
	}
	out, e := preflightOutput(path, indexPath, journalPaths)
	if e != nil {
		return result, e
	}
	lock := out + ".lock"
	if e = os.Mkdir(lock, 0700); e != nil {
		if os.IsExist(e) {
			return result, delivery.Fail("record_busy", "output lock exists; never removed automatically")
		}
		return result, persistence("create output lock")
	}
	failure := func(point string) bool { return fail != nil && fail(point) != nil }
	var tmp string
	var file *os.File
	defer func() {
		if file != nil {
			if e := file.Close(); e != nil {
				err = persistence("close output temporary file")
			}
		}
		if tmp != "" {
			injected := failure("cleanup-temp")
			e := os.Remove(tmp)
			if injected || (e != nil && !os.IsNotExist(e)) {
				err = persistence("remove owned output temporary file")
			}
		}
		injected := failure("cleanup-lock")
		e := os.Remove(lock)
		if injected || e != nil {
			err = persistence("remove owned output lock")
		}
		if err != nil {
			result.Output = nil
		}
	}()
	if e = absent(out); e != nil {
		return result, e
	}
	file, e = os.CreateTemp(filepath.Dir(out), ".rio-record-*.tmp")
	if e != nil {
		return result, persistence("create output temporary file")
	}
	tmp = file.Name()
	if failure("write") {
		return result, persistence("write output")
	}
	if _, e = file.Write(raw); e != nil {
		return result, persistence("write output")
	}
	if failure("sync") {
		return result, persistence("sync output")
	}
	if e = file.Sync(); e != nil {
		return result, persistence("sync output")
	}
	if failure("close") {
		return result, persistence("close output")
	}
	if e = file.Close(); e != nil {
		file = nil
		return result, persistence("close output")
	}
	file = nil
	if failure("publish") {
		return result, persistence("publish output")
	}
	if e = os.Link(tmp, out); e != nil {
		return result, persistence("publish absent output")
	}
	result.OutputMayExist = true
	if failure("directory-sync") {
		return result, persistence("sync output directory")
	}
	if e = syncDirectory(filepath.Dir(out)); e != nil {
		return result, persistence("sync output directory")
	}
	if failure("read-back") {
		return result, persistence("read back published output")
	}
	saved, e := delivery.ReadBounded(out, FileLimit)
	if e != nil || !bytes.Equal(saved, raw) {
		return result, persistence("read back published output")
	}
	if _, e = Parse(saved, validate, retryPolicy...); e != nil {
		return result, persistence("validate published output")
	}
	result.Output = &Output{Path: path, SHA256: delivery.Digest(saved), Size: int64(len(saved))}
	return result, nil
}
func persistence(field string) error { return delivery.Fail("persistence_failed", field) }
func absent(path string) error {
	if _, e := os.Lstat(path); e == nil {
		return delivery.Fail("output_exists", "new output file required")
	} else if !os.IsNotExist(e) {
		return delivery.Fail("invalid_output", "output path")
	}
	return nil
}
func canonicalParent(path string) (string, error) {
	abs, e := filepath.Abs(path)
	if e != nil {
		return "", delivery.Fail("invalid_output", "output path")
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(abs))
	if e != nil {
		return "", delivery.Fail("invalid_output", "existing parent directory required")
	}
	st, e := os.Stat(parent)
	if e != nil || !st.IsDir() {
		return "", delivery.Fail("invalid_output", "existing parent directory required")
	}
	return filepath.Join(parent, filepath.Base(abs)), nil
}

// inside compares existing ancestor identities, not spelling. The leaf may not
// exist yet, and filesystems can resolve case/normalization aliases differently.
func inside(path, root string) bool {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		if samePath(current, root) {
			return true
		}
		if filepath.Dir(current) == current {
			return false
		}
	}
}
func samePath(a, b string) bool {
	if a == b {
		return true
	}
	sa, ea := os.Stat(a)
	sb, eb := os.Stat(b)
	return ea == nil && eb == nil && os.SameFile(sa, sb)
}
func preflightOutput(path, indexPath string, journals []string) (string, error) {
	out, e := canonicalParent(path)
	if e != nil {
		return "", e
	}
	if e = absent(out); e != nil {
		return "", e
	}
	source, e := filepath.EvalSymlinks(indexPath)
	if e != nil {
		return "", delivery.Fail("read_failed", "source index")
	}
	source, e = filepath.Abs(source)
	if e != nil {
		return "", delivery.Fail("invalid_output", "source index path")
	}
	for _, candidate := range []string{out, out + ".lock"} {
		if samePath(candidate, source) || inside(source, candidate) {
			return "", delivery.Fail("output_collision", "output or lock collides with index")
		}
	}
	for _, path := range journals {
		root, e := canonicalParent(path)
		if e != nil {
			return "", e
		}
		collision, e := journalNamespaceCollision(out, root)
		if e != nil {
			return "", e
		}
		if collision {
			return "", delivery.Fail("output_collision", "output or lock collides with selected journal")
		}

	}
	return out, nil
}

// Materialize the reserved sibling namespace under its normal exclusive lock so
// even a nonexistent differently-cased lock name has a real identity to compare.
// This metadata-only preflight never reads events and releases every journal lock
// before output publication. It also respects case-sensitive directory behavior.
func journalNamespaceCollision(out, root string) (collision bool, err error) {
	err = record.WithJournalLock(root, func(root, lock string) error {
		for _, candidate := range []string{out, out + ".lock"} {
			for _, namespace := range []string{root, lock} {
				if inside(candidate, namespace) || inside(namespace, candidate) {
					collision = true
					return nil
				}
			}
		}
		return nil
	})
	return collision, err
}
