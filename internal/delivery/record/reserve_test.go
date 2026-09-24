package record

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReserveOwnership(t *testing.T) {
	p := filepath.Join(t.TempDir(), "attempt")
	r, e := Reserve(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := Reserve(p); e == nil {
		t.Fatal("competing reservation succeeded")
	}
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("reservation published intent")
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = Reserve(p)
	if e != nil {
		t.Fatal(e)
	}
	w, e := r.Create(intent())
	if e != nil {
		t.Fatal(e)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := Reserve(p); e == nil {
		t.Fatal("old reservation released writer lock")
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := Reserve(p); e == nil {
		t.Fatal("existing record reserved")
	}
}

func TestBatchReserveConflictReleasesAll(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	os.Mkdir(b, 0700)
	if _, e := ReserveAll([]string{b, a}); e == nil {
		t.Fatal("existing path accepted")
	}
	if _, e := os.Stat(a + ".lock"); !os.IsNotExist(e) {
		t.Fatal("earlier lock leaked")
	}
	if _, e := os.Stat(a); !os.IsNotExist(e) {
		t.Fatal("intent committed during reservation")
	}
}
