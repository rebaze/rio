package receipt

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestReservationRefusesExistingAndConcurrentReceipt(t *testing.T) {
	out := t.TempDir()
	dest := filepath.Join(out, "record.json")
	var wg sync.WaitGroup
	var mu sync.Mutex
	var owners []*Store
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, e := Start(out, dest, "pipeline", "0.7.0")
			if e == nil {
				mu.Lock()
				owners = append(owners, s)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(owners) != 1 {
		t.Fatalf("%d reservation owners", len(owners))
	}
	s := owners[0]
	defer s.Close()
	d := fixture()
	d.Run.ID = s.ID
	if _, e := s.Publish(d); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(dest)
	if _, e := s.Publish(d); e == nil {
		t.Fatal("replaced completed receipt")
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := Start(out, dest, "pipeline", "0.7.0"); e == nil {
		t.Fatal("reserved existing receipt")
	}
	after, _ := os.ReadFile(dest)
	if !bytes.Equal(raw, after) {
		t.Fatal("receipt changed")
	}
}
func TestFreshRunsHaveIndependentOutputs(t *testing.T) {
	out := t.TempDir()
	a, e := Start(out, "", "normalize", "0.7.0")
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := Start(out, "", "normalize", "0.7.0")
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	if a.ID == b.ID || a.Dir == b.Dir || a.Path == b.Path {
		t.Fatal("run collision")
	}
	for _, s := range []*Store{a, b} {
		d, e := ReadCheckpoint(s.Dir)
		if e != nil || d.Run.Outcome != "incomplete" || d.Run.FinishedAt != "" {
			t.Fatalf("initial durable state: %#v %v", d, e)
		}
	}
}
func TestCheckpointRecoveryDoesNotPublishOrExecute(t *testing.T) {
	s, e := Start(t.TempDir(), "", "pipeline", "0.7.0")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	d := fixture()
	d.Run.ID = s.ID
	d.Run.Outcome = "incomplete"
	d.Run.FinishedAt = ""
	if e = s.Checkpoint(d); e != nil {
		t.Fatal(e)
	}
	got, e := ReadCheckpoint(s.Dir)
	if e != nil || len(got.Deliveries) != 1 || got.Run.Outcome != "incomplete" {
		t.Fatalf("%#v %v", got, e)
	}
	if _, e = os.Stat(s.Path); !os.IsNotExist(e) {
		t.Fatal("checkpoint appeared as completed public receipt")
	}
	// A torn temporary write is not a committed checkpoint.
	if e = os.WriteFile(filepath.Join(s.Dir, ".internal", ".pending-broken"), []byte("{"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadCheckpoint(s.Dir); e != nil {
		t.Fatal(e)
	}
}
func TestPublicationFailureRetainsLocalRecovery(t *testing.T) {
	s, e := Start(t.TempDir(), "", "pipeline", "0.7.0")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	d := fixture()
	d.Run.ID = s.ID
	// A competing writer cannot be overwritten, even while our lock is held.
	if e = os.WriteFile(s.Path, []byte("competing file"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Publish(d); e == nil {
		t.Fatal("overwrote racing file")
	}
	got, e := ReadCheckpoint(s.Dir)
	if e != nil || got.Run.Outcome != "success" {
		t.Fatalf("lost committed facts: %v", e)
	}
	b, _ := os.ReadFile(s.Path)
	if string(b) != "competing file" {
		t.Fatal("replaced file")
	}
}
func TestCheckpointRefusesWrongRunAndClosedOwner(t *testing.T) {
	s, e := Start(t.TempDir(), "", "pipeline", "0.7.0")
	if e != nil {
		t.Fatal(e)
	}
	d := fixture()
	if e = s.Checkpoint(d); e == nil {
		t.Fatal("wrong run accepted")
	}
	s.Close()
	d.Run.ID = s.ID
	if e = s.Checkpoint(d); e == nil {
		t.Fatal("closed writer accepted")
	}
}

func TestInvalidExplicitReceiptCreatesNoRunDirectories(t *testing.T) {
	for _, kind := range []string{"missing-parent", "existing-file", "existing-lock"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "output")
			path := filepath.Join(dir, "record.json")
			switch kind {
			case "missing-parent":
				path = filepath.Join(dir, "missing", "record.json")
			case "existing-file":
				if e := os.WriteFile(path, []byte("immutable"), 0600); e != nil {
					t.Fatal(e)
				}
			case "existing-lock":
				if e := os.Mkdir(path+".lock", 0700); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := Start(out, path, "pipeline", "0.7.0"); e == nil {
				t.Fatal("invalid destination accepted")
			}
			if _, e := os.Stat(out); !os.IsNotExist(e) {
				t.Fatalf("created output before destination refusal: %v", e)
			}
		})
	}
}
