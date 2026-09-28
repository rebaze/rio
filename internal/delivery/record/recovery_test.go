package record

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryReadsCommittedPrefixWithoutBreakingCrashLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "journal")
	w, e := Create(p, intent())
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	if e = w.Append("submission", submission()); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(p, ".event-torn.tmp"), []byte("{"), 0600); e != nil {
		t.Fatal(e)
	}
	s, e := RecoverySnapshot(p, 1<<20)
	if e != nil || s.Disposition != "accepted" || len(s.Events) != 2 {
		t.Fatalf("%#v %v", s, e)
	}
	if _, e = os.Stat(p + ".lock"); e != nil {
		t.Fatal("lock removed", e)
	}
	if _, e = Read(p); e == nil {
		t.Fatal("normal writer lock bypassed")
	}
	if _, e = RecoverySnapshot(p, 1); e == nil {
		t.Fatal("recovery byte budget bypassed")
	}
}
