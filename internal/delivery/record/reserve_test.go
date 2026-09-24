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

func TestReserveStaleAndAliases(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "attempt")
	os.Mkdir(p+".lock", 0700)
	if _, e := Reserve(p); e == nil {
		t.Fatal("stale lock auto-broken")
	}
	if _, e := os.Stat(p + ".lock"); e != nil {
		t.Fatal(e)
	}
	os.Remove(p + ".lock")
	alias := filepath.Join(t.TempDir(), "alias")
	if e := os.Symlink(dir, alias); e != nil {
		t.Skip("symlink privileges unavailable")
	}
	if _, e := ReserveAll([]string{p, filepath.Join(alias, "attempt")}); e == nil {
		t.Fatal("canonical alias reserved twice")
	}
	if _, e := os.Stat(p + ".lock"); !os.IsNotExist(e) {
		t.Fatal("alias conflict leaked lock")
	}
	os.Symlink(filepath.Join(dir, "missing"), p)
	if _, e := Reserve(p); e == nil {
		t.Fatal("symlink record accepted")
	}
}
