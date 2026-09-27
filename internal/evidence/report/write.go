package report

import (
	"bytes"
	"os"
	"path/filepath"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/evidence"
)

// Publish atomically creates a new HTML file. Only its own temporary is removed;
// existing files, symlinks and racing creators are never replaced.
func Publish(output, input string, raw []byte) (result evidence.Publication, err error) {
	if int64(len(raw)) > HTMLLimit {
		return result, delivery.Fail("size_limit", "maximum report HTML bytes")
	}
	out, e := filepath.Abs(output)
	if e != nil {
		return result, delivery.Fail("invalid_output", "report output path")
	}
	source, e := filepath.Abs(input)
	if e != nil {
		return result, delivery.Fail("invalid_output", "input record path")
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(out))
	if e != nil {
		return result, delivery.Fail("invalid_output", "existing output parent required")
	}
	out = filepath.Join(parent, filepath.Base(out))
	sourceParent, e := filepath.EvalSymlinks(filepath.Dir(source))
	if e != nil {
		return result, delivery.Fail("invalid_output", "input record parent")
	}
	source = filepath.Join(sourceParent, filepath.Base(source))
	if out == source {
		return result, delivery.Fail("output_collision", "report cannot replace its JSON source")
	}
	if _, e = os.Lstat(out); e == nil {
		result.OutputMayExist = true
		return result, delivery.Fail("output_exists", "new report output required")
	} else if !os.IsNotExist(e) {
		return result, delivery.Fail("invalid_output", "report output path")
	}
	f, e := os.CreateTemp(parent, ".rio-report-*.tmp")
	if e != nil {
		return result, delivery.Fail("persistence_failed", "create report temporary")
	}
	tmp := f.Name()
	open := true
	defer func() {
		if open {
			if e := f.Close(); e != nil {
				err = delivery.Fail("persistence_failed", "close report temporary")
			}
		}
		if e := os.Remove(tmp); e != nil && !os.IsNotExist(e) {
			err = delivery.Fail("persistence_failed", "remove owned report temporary")
		}
		if err != nil {
			result.Output = nil
		}
	}()
	if _, e = f.Write(raw); e != nil {
		return result, delivery.Fail("persistence_failed", "write report")
	}
	if e = f.Sync(); e != nil {
		return result, delivery.Fail("persistence_failed", "sync report")
	}
	e = f.Close()
	open = false
	if e != nil {
		return result, delivery.Fail("persistence_failed", "close report")
	}
	if e = os.Link(tmp, out); e != nil {
		_, st := os.Lstat(out)
		result.OutputMayExist = os.IsExist(e) || st == nil
		return result, delivery.Fail("persistence_failed", "publish absent report")
	}
	result.OutputMayExist = true
	if e = syncDirectory(parent); e != nil {
		return result, delivery.Fail("persistence_failed", "sync report directory")
	}
	saved, e := delivery.ReadBounded(out, HTMLLimit)
	if e != nil || !bytes.Equal(saved, raw) {
		return result, delivery.Fail("persistence_failed", "read back report")
	}
	result.Output = &evidence.Output{Path: output, SHA256: delivery.Digest(saved), Size: int64(len(saved))}
	return result, nil
}
