package record

import (
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func intent() Intent {
	h := strings.Repeat("a", 64)
	return Intent{RioVersion: "test", Source: delivery.Source{IndexSHA256: h, ArtifactID: "app", OutputSHA256: h, Gate: "ok"}, Payloads: []delivery.PayloadRef{{Role: "sbom", MediaType: "application/vnd.cyclonedx+json", SHA256: h, Size: 10, SourceSHA256: h, Transformation: "identity"}}, Binding: "app-security", Destination: delivery.Description{Type: "test", DestinationName: "security", Identity: json.RawMessage(`{"object":"a"}`), Options: json.RawMessage(`{}`), CredentialRefs: []string{}, Capabilities: []string{"submit"}}, ConfigSHA256: h}
}
func submission() json.RawMessage {
	b, _ := json.Marshal(delivery.Submission{Disposition: "accepted", References: []delivery.Reference{}, Observations: []delivery.Observation{{Kind: "acknowledgment", Value: "accepted", Origin: "receiver", Code: "accepted", References: []delivery.Reference{}}}})
	return b
}
func TestJournalLockAndImmutableEvents(t *testing.T) {
	p := filepath.Join(t.TempDir(), "record")
	w, e := Create(p, intent())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Open(p); e == nil {
		t.Fatal("concurrent writer")
	}
	before, _ := os.ReadFile(filepath.Join(p, eventName(0)))
	if e = w.Append("submission", submission()); e != nil {
		t.Fatal(e)
	}
	if e = w.Append("submission", submission()); e == nil {
		t.Fatal("second submission accepted")
	}
	w.Close()
	after, _ := os.ReadFile(filepath.Join(p, eventName(0)))
	if string(before) != string(after) {
		t.Fatal("intent changed")
	}
	s, e := Read(p)
	if e != nil || s.Disposition != "accepted" || len(s.Events) != 2 {
		t.Fatal(s, e)
	}
	if _, e = Create(p, intent()); e == nil {
		t.Fatal("record reused")
	}
}
func TestJournalIntentOnlyAndTemps(t *testing.T) {
	p := filepath.Join(t.TempDir(), "record")
	w, e := Create(p, intent())
	if e != nil {
		t.Fatal(e)
	}
	w.Close()
	os.WriteFile(filepath.Join(p, ".event-orphan.tmp"), []byte("partial"), 0600)
	s, e := Read(p)
	if e != nil || s.Disposition != "unknown" || len(s.OrphanTemps) != 1 {
		t.Fatal(s, e)
	}
	os.Mkdir(p+".lock", 0700)
	if _, e = Read(p); e == nil {
		t.Fatal("stale lock ignored")
	}
	if _, e = os.Stat(p + ".lock"); e != nil {
		t.Fatal("stale lock removed")
	}
}
func TestJournalCorruption(t *testing.T) {
	for _, kind := range []string{"gap", "id", "version", "duplicate", "null", "empty"} {
		t.Run(kind, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "record")
			w, e := Create(p, intent())
			if e != nil {
				t.Fatal(e)
			}
			w.Append("submission", submission())
			w.Close()
			f := filepath.Join(p, eventName(1))
			b, _ := os.ReadFile(f)
			var m map[string]any
			json.Unmarshal(b, &m)
			switch kind {
			case "gap":
				os.Rename(f, filepath.Join(p, eventName(2)))
			case "id":
				m["attemptId"] = strings.Repeat("b", 32)
			case "version":
				m["schemaVersion"] = 2
			case "null":
				m["data"] = nil
			case "duplicate":
				b = append([]byte(`{"sequence":1,`), b[1:]...)
				os.WriteFile(f, b, 0600)
			case "empty":
				os.Remove(filepath.Join(p, eventName(0)))
				os.Remove(f)
			}
			if kind == "id" || kind == "version" || kind == "null" {
				b, _ = json.Marshal(m)
				os.WriteFile(f, b, 0600)
			}
			if _, e = Read(p); e == nil {
				t.Fatal("corruption accepted")
			}
		})
	}
}
func TestJournalPersistenceFailures(t *testing.T) {
	for _, point := range []string{"write", "sync", "close", "rename", "directory-sync"} {
		t.Run(point, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "record")
			w, e := Create(p, intent())
			if e != nil {
				t.Fatal(e)
			}
			w.fail = func(s string) error {
				if s == point {
					return delivery.Fail("persistence_failed", "injected")
				}
				return nil
			}
			if e = w.Append("submission", submission()); e == nil {
				t.Fatal("failure ignored")
			}
			w.Close()
			s, e := Read(p)
			if e != nil {
				t.Fatal(e)
			}
			if point != "directory-sync" && s.Disposition != "unknown" {
				t.Fatal("uncommitted result accepted")
			}
		})
	}
}
func TestJournalSymlink(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "record")
	os.Mkdir(p, 0700)
	link := filepath.Join(dir, "link")
	if e := os.Symlink(p, link); e != nil {
		t.Skip("symlink unavailable")
	}
	if _, e := Open(link); e == nil {
		t.Fatal("symlink accepted")
	}
}
func TestJournalCrash(t *testing.T) {
	if os.Getenv("RIO_JOURNAL_CRASH") == "1" {
		p := os.Getenv("RIO_JOURNAL_PATH")
		if _, e := Create(p, intent()); e != nil {
			os.Exit(7)
		}
		os.Exit(0)
	}
	for _, phase := range []string{"after-intent"} {
		t.Run(phase, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "record")
			cmd := exec.Command(os.Args[0], "-test.run=^TestJournalCrash$")
			cmd.Env = append(os.Environ(), "RIO_JOURNAL_CRASH=1", "RIO_JOURNAL_PATH="+p)
			if b, e := cmd.CombinedOutput(); e != nil {
				t.Fatal(e, string(b))
			}
			if _, e := Read(p); e == nil {
				t.Fatal("crash lock not retained")
			}
			if e := os.Remove(p + ".lock"); e != nil {
				t.Fatal(e)
			}
			s, e := Read(p)
			if e != nil || s.Disposition != "unknown" {
				t.Fatal(s, e)
			}
			if _, e = Create(p, intent()); e == nil {
				t.Fatal("replay authorized")
			}
		})
	}
}

func TestOpenInvalidSnapshotReportsCleanupFailure(t *testing.T) {
	p := filepath.Join(t.TempDir(), "record")
	os.Mkdir(p, 0700)
	w, e := open(p, func(w *Writer) {
		if err := os.WriteFile(filepath.Join(w.lock, "obstruction"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	})
	if w != nil || e == nil || !strings.Contains(e.Error(), "persistence_failed") {
		t.Fatal("cleanup error hidden", w, e)
	}
}
func TestCreateExistingRecordReportsCleanupFailure(t *testing.T) {
	p := filepath.Join(t.TempDir(), "record")
	os.Mkdir(p, 0700)
	w, e := create(p, intent(), func(w *Writer) {
		if err := os.WriteFile(filepath.Join(w.lock, "obstruction"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	})
	if w != nil || e == nil || !strings.Contains(e.Error(), "persistence_failed") {
		t.Fatal("cleanup error hidden", w, e)
	}
}
