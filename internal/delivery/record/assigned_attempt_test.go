package record

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreassignedAttemptIDIsCommitted(t *testing.T) {
	raw, err := os.ReadFile("testdata/intent.json")
	if err != nil {
		t.Fatal(err)
	}
	var event Event
	json.Unmarshal(raw, &event)
	var intent Intent
	json.Unmarshal(event.Data, &intent)
	path := filepath.Join(t.TempDir(), "journal")
	r, err := Reserve(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// A descriptor must be able to name the actual attempt before Submit begins.
	assigned, ok := any(r).(interface {
		CreateWithAttemptID(Intent, string) (*Writer, error)
	})
	if !ok {
		t.Fatal("reservation cannot bind a preassigned attempt ID")
	}
	id := strings.Repeat("a", 32)
	w, err := assigned.CreateWithAttemptID(intent, id)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	snapshot, err := w.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Events[0].AttemptID != id {
		t.Fatal("descriptor/journal identity differs")
	}
}
