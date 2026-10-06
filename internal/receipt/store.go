package receipt

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rebaze/rio/internal/delivery"
)

// Store owns a fresh invocation directory and a public-output reservation.
// Immutable checkpoints are local recovery facts, never a public source bundle.
// A crashed owner's reservation is never silently broken by another invocation.
type Store struct {
	ID       string
	Dir      string
	Path     string
	Initial  Document
	sequence int
	closed   bool
}
type Publication struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

func Start(out, path, operation, version string, protected ...string) (*Store, error) {
	idBytes := make([]byte, 16)
	if _, e := rand.Read(idBytes); e != nil {
		return nil, e
	}
	id := fmt.Sprintf("run-%x", idBytes)
	root, e := filepath.Abs(out)
	if e != nil {
		return nil, e
	}
	// Validate the prospective run namespace before creating any directories:
	// even an output root inside an existing journal must remain untouched.
	if e = CheckDestination(filepath.Join(root, "runs", id, "record.json"), protected); e != nil {
		return nil, e
	}
	if path != "" {
		// Validate explicit locations before creating any run state. The default
		// destination's parent is the fresh directory created below.
		path, e = resolveReceiptPath(path)
		if e != nil {
			return nil, e
		}
		if e = absent(path); e != nil {
			return nil, e
		}
		if e = absent(path + ".lock"); e != nil {
			return nil, e
		}
		if e = CheckDestination(path, protected); e != nil {
			return nil, e
		}
	}
	if e = os.MkdirAll(filepath.Join(root, "runs"), 0700); e != nil {
		return nil, e
	}
	dir := filepath.Join(root, "runs", id)
	if e = os.Mkdir(dir, 0700); e != nil {
		return nil, e
	}
	if e = os.Mkdir(filepath.Join(dir, ".internal"), 0700); e != nil {
		return nil, e
	}
	if path == "" {
		path = filepath.Join(dir, "record.json")
	}
	path, e = resolveReceiptPath(path)
	if e != nil {
		return nil, e
	}
	if e = CheckDestination(path, protected); e != nil {
		return nil, e
	}
	if e = absent(path); e != nil {
		return nil, e
	}
	if e = os.Mkdir(path+".lock", 0700); e != nil {
		return nil, fmt.Errorf("reserve receipt (existing locks are never removed automatically): %w", e)
	}
	s := &Store{ID: id, Dir: dir, Path: path}
	if e = absent(path); e != nil {
		s.Close()
		return nil, e
	}
	s.Initial = Document{Kind: Kind, SchemaVersion: 1, RioVersion: version, Run: Run{ID: id, Operation: operation, StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Outcome: "incomplete", Stages: map[string]string{"intake": "not-attempted", "normalize": "not-attempted", "checks": "not-attempted", "delivery": "not-attempted"}}}
	if e = s.Checkpoint(s.Initial); e != nil {
		s.Close()
		return nil, e
	}
	return s, nil
}
func resolveReceiptPath(path string) (string, error) {
	absolute, e := filepath.Abs(path)
	if e != nil {
		return "", e
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(absolute))
	if e != nil {
		return "", fmt.Errorf("receipt parent must exist: %w", e)
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}

func (s *Store) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return os.Remove(s.Path + ".lock")
}
func (s *Store) Checkpoint(d Document) error {
	if s.closed || d.Run.ID != s.ID {
		return invalid("checkpoint owner")
	}
	raw, e := Marshal(d)
	if e != nil {
		return e
	}
	path := filepath.Join(s.Dir, ".internal", fmt.Sprintf("checkpoint-%08d.json", s.sequence))
	if _, e = publishNew(path, raw); e != nil {
		return e
	}
	s.sequence++
	return nil
}
func (s *Store) Publish(d Document) (Publication, error) {
	if d.Run.Outcome == "incomplete" {
		return Publication{}, invalid("cannot publish incomplete invocation as completed")
	}
	if e := s.Checkpoint(d); e != nil {
		return Publication{}, e
	}
	raw, e := Marshal(d)
	if e != nil {
		return Publication{}, e
	}
	return publishNew(s.Path, raw)
}

// ReadCheckpoint reads only explicitly requested local recovery state. It never
// follows referenced paths, constructs clients, or retries an upload. The caller
// must account for journals newer than this checkpoint before claiming completion.
func ReadCheckpoint(dir string) (Document, error) {
	entries, e := os.ReadDir(filepath.Join(dir, ".internal"))
	if e != nil {
		return Document{}, e
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "checkpoint-") && strings.HasSuffix(name, ".json") {
			if len(name) != len("checkpoint-00000000.json") || entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
				return Document{}, invalid("checkpoint file")
			}
			for _, c := range name[11:19] {
				if c < '0' || c > '9' {
					return Document{}, invalid("checkpoint name")
				}
			}
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return Document{}, invalid("no committed checkpoint")
	}
	sort.Strings(names)
	raw, e := delivery.ReadBounded(filepath.Join(dir, ".internal", names[len(names)-1]), MaxBytes)
	if e != nil {
		return Document{}, e
	}
	return Parse(raw)
}
func absent(path string) error {
	if _, e := os.Lstat(path); e == nil {
		return fmt.Errorf("receipt destination already exists: %s", path)
	} else if !os.IsNotExist(e) {
		return e
	}
	return nil
}

// publishNew uses a fully synced sibling temporary followed by an atomic hard
// link. Even an uncooperative creator racing the lock cannot be overwritten.
func publishNew(path string, raw []byte) (result Publication, err error) {
	if err = absent(path); err != nil {
		return result, err
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".pending-receipt-*")
	if e != nil {
		return result, e
	}
	temp := f.Name()
	defer func() {
		_ = f.Close()
		if e := os.Remove(temp); e != nil && !os.IsNotExist(e) && err == nil {
			err = e
		}
	}()
	if _, err = f.Write(raw); err != nil {
		return result, err
	}
	if err = f.Sync(); err != nil {
		return result, err
	}
	if err = f.Close(); err != nil {
		return result, err
	}
	if err = os.Link(temp, path); err != nil {
		return result, err
	}
	// Return the possible output location even when durability/readback fails.
	result.Path = path
	if err = syncDirectory(filepath.Dir(path)); err != nil {
		return result, err
	}
	saved, e := delivery.ReadBounded(path, int64(len(raw)))
	if e != nil {
		return result, e
	}
	if !bytes.Equal(saved, raw) {
		return result, fmt.Errorf("receipt readback differs")
	}
	result.SHA256 = delivery.Digest(saved)
	result.Size = len(saved)
	return result, nil
}

// WriteRecovery binds assigned attempts to their local journals before requests.
// This internal mapping is never copied into the public receipt.
func (s *Store) WriteRecovery(raw []byte) error {
	if s.closed || len(raw) > MaxBytes {
		return invalid("recovery owner or size")
	}
	_, err := publishNew(filepath.Join(s.Dir, ".internal", "attempts.json"), raw)
	return err
}

// PublishRecovered publishes a fresh immutable snapshot of the original run.
// Unlike normal completion, an explicitly recovered snapshot may be incomplete.
func PublishRecovered(path string, d Document) (Publication, error) {
	if e := CheckDestination(path, nil); e != nil {
		return Publication{}, e
	}
	raw, e := Marshal(d)
	if e != nil {
		return Publication{}, e
	}
	return publishNew(path, raw)
}
