package evidence

import (
	"os"
	"path/filepath"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/batchrecord"
	"github.com/rebaze/rio/internal/delivery/record"
)

// CollectV2 reads only explicitly selected sources and descriptor-bound hints.
// A missing bound journal is a gap. An explicitly named missing journal refuses.
func CollectV2(indexPath string, batchPaths, journalPaths []string, version string, validate Validator, retryPolicy ...RetryValidator) (Document, error) {
	if len(batchPaths) > batchrecord.MaxBatches || len(journalPaths) > MaxJournalsV2 {
		return Document{}, limitError()
	}
	remaining := SourceLimit
	read := func(path string, bound int64) ([]byte, error) {
		if bound > remaining {
			bound = remaining
		}
		raw, err := delivery.ReadBounded(path, bound)
		if err == nil {
			remaining -= int64(len(raw))
		}
		return raw, err
	}
	var indexRaw []byte
	var err error
	if indexPath != "" {
		indexRaw, err = read(indexPath, delivery.IndexLimit)
		if err != nil {
			return Document{}, err
		}
	}
	type selectedPair struct {
		path string
		pair batchrecord.Pair
	}
	pairs := []selectedPair{}
	batches := []capturedBatch{}
	protected := []string{}
	seenBatch := map[string]bool{}
	for _, path := range batchPaths {
		raw, err := read(path, batchrecord.SourceLimit)
		if err != nil {
			return Document{}, err
		}
		desc, err := batchrecord.ParseDescriptor(raw)
		if err != nil {
			return Document{}, err
		}
		sha := delivery.Digest(raw)
		if seenBatch[sha] {
			return Document{}, delivery.Fail("duplicate_batch", "batch selected more than once")
		}
		seenBatch[sha] = true
		protected = append(protected, path)
		if indexRaw == nil {
			indexPath, err = batchrecord.ResolveHint(path, desc.Index.PathHint)
			if err != nil {
				return Document{}, err
			}
			indexRaw, err = read(indexPath, delivery.IndexLimit)
			if err != nil {
				return Document{}, err
			}
		}
		if err = batchrecord.ValidateIndex(desc, indexRaw); err != nil {
			return Document{}, err
		}
		completionPath, err := batchrecord.ResolveHint(path, desc.CompletionPathHint)
		if err != nil {
			return Document{}, err
		}
		protected = append(protected, completionPath)
		var completion []byte
		if _, err = os.Lstat(completionPath); err == nil {
			completion, err = read(completionPath, batchrecord.SourceLimit)
			if err != nil {
				return Document{}, err
			}
		} else if !os.IsNotExist(err) {
			return Document{}, delivery.Fail("read_failed", "batch completion")
		}
		batches = append(batches, capturedBatch{raw, completion})
		for _, pair := range desc.Pairs {
			hint, err := batchrecord.ResolveHint(path, pair.JournalPathHint)
			if err != nil {
				return Document{}, err
			}
			pairs = append(pairs, selectedPair{hint, pair})
		}
	}
	if indexRaw == nil {
		return Document{}, delivery.Fail("invalid_index", "index or batch required")
	}
	if len(pairs)+len(journalPaths) > MaxJournalsV2 {
		return Document{}, limitError()
	}
	captures := []record.Capture{}
	events := 0
	paths := []string{}
	cache := map[string]record.Capture{}
	selectedIDs := map[string]bool{}
	type mismatch struct {
		pair     batchrecord.Pair
		snapshot record.Snapshot
	}
	mismatches := []mismatch{}
	selectCapture := func(c record.Capture) {
		captures = append(captures, c)
		selectedIDs[c.Snapshot.Events[0].AttemptID] = true
	}
	capture := func(path string, optional bool) (record.Capture, bool, error) {
		if path == "" {
			return record.Capture{}, false, delivery.Fail("invalid_record_path", "journal path")
		}
		key, e := filepath.Abs(path)
		if e != nil {
			return record.Capture{}, false, delivery.Fail("invalid_record_path", "journal path")
		}
		if c, ok := cache[key]; ok {
			return c, true, nil
		}
		if optional {
			missing, err := missingJournal(path)
			if err != nil {
				return record.Capture{}, false, err
			}
			if missing {
				return record.Capture{}, false, nil
			}
		}
		c, err := record.CaptureRead(path, remaining, MaxEvents-events)
		if err != nil {
			return c, false, err
		}
		for _, raw := range c.RawEvents {
			remaining -= int64(len(raw))
		}
		events += len(c.RawEvents)
		if remaining < 0 || events > MaxEvents {
			return c, false, limitError()
		}
		cache[key] = c
		return c, true, nil
	}
	for _, p := range pairs {
		paths = append(paths, p.path)
		c, present, err := capture(p.path, true)
		if err != nil {
			return Document{}, err
		}
		if present {
			if c.Snapshot.Events[0].AttemptID != p.pair.AttemptID {
				mismatches = append(mismatches, mismatch{p.pair, c.Snapshot})
				continue
			}
			if err = batchrecord.CheckPairJournal(p.pair, c.Snapshot); err != nil {
				return Document{}, err
			}
			selectCapture(c)
		}
	}
	for _, path := range journalPaths {
		paths = append(paths, path)
		c, _, err := capture(path, false)
		if err != nil {
			return Document{}, err
		}
		selectCapture(c)
	}
	for _, m := range mismatches {
		// A slot not used by an older batch can later contain a new attempt. Retain
		// the older gap only when the actual attempt is independently selected and
		// compatible; never silently attribute it to the old descriptor.
		if !selectedIDs[m.snapshot.Events[0].AttemptID] || !compatible(m.pair.Intent, m.snapshot.Intent, retryPolicy...) {
			return Document{}, delivery.Fail("evidence_mismatch", "journal path contains a different unselected or incompatible attempt")
		}
	}
	d, err := assembleV2(indexRaw, captures, batches, version, validate, retryPolicy...)
	if err != nil {
		return Document{}, err
	}
	d.sourceIndexPath = indexPath
	d.sourcePaths = protected
	d.journalPaths = paths
	return d, nil
}
func missingJournal(path string) (missing bool, err error) {
	if _, e := os.Stat(filepath.Dir(path)); os.IsNotExist(e) {
		return true, nil
	} else if e != nil {
		return false, delivery.Fail("read_failed", "journal parent")
	}
	err = record.WithJournalLock(path, func(root, _ string) error {
		if _, e := os.Lstat(root); os.IsNotExist(e) {
			missing = true
			return nil
		} else if e != nil {
			return delivery.Fail("read_failed", "selected journal")
		}
		return nil
	})
	return missing, err
}

// CollectionPaths is used only for publication collision checks, never for
// rendering or inspection. Parsed portable records have no local source paths.
func (d Document) CollectionPaths() (string, []string, []string) {
	return d.sourceIndexPath, append([]string{}, d.journalPaths...), append([]string{}, d.sourcePaths...)
}
