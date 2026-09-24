package evidence

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishNewFileAndRefuseOverwrite(t *testing.T) {
	d, ip, p, q := collectFixture(t)
	b, e := Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(t.TempDir(), "record.json")
	r, e := Publish(out, ip, []string{p, q}, b, validateFixture)
	if e != nil || !r.OutputMayExist || r.Output == nil || r.Output.Size != int64(len(b)) {
		t.Fatal(r, e)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(b, got) {
		t.Fatal("published wrong bytes")
	}
	if _, e = Publish(out, ip, []string{p, q}, b, validateFixture); e == nil {
		t.Fatal("overwrote output")
	}
	if _, e = os.Stat(out + ".lock"); !os.IsNotExist(e) {
		t.Fatal("owned lock left")
	}
}
func TestPublishRefusesSourceNamespaces(t *testing.T) {
	d, ip, p, q := collectFixture(t)
	b, _ := Marshal(d)
	for _, out := range []string{ip, p, p + ".lock", filepath.Join(p, "record.json"), filepath.Join(p, "00000000000000000002.json"), filepath.Join(p, ".lock"), filepath.Join(filepath.Dir(ip), "missing", "record.json")} {
		if _, e := Publish(out, ip, []string{p, q}, b, validateFixture); e == nil {
			t.Fatal("source collision accepted", out)
		}
	}
	lockIndex := filepath.Join(t.TempDir(), "result.lock")
	raw, _ := os.ReadFile(ip)
	os.WriteFile(lockIndex, raw, 0600)
	if _, e := Publish(lockIndex[:len(lockIndex)-5], lockIndex, nil, b, validateFixture); e == nil {
		t.Fatal("output lock collides with index")
	}
	after, _ := os.ReadFile(ip)
	if !bytes.Equal(raw, after) {
		t.Fatal("source modified")
	}
}
func TestPublishPathAliasesAndBusyLock(t *testing.T) {
	d, ip, p, _ := collectFixture(t)
	b, _ := Marshal(d)
	parent := t.TempDir()
	out := filepath.Join(parent, "record.json")
	os.Mkdir(out+".lock", 0700)
	if _, e := Publish(out, ip, []string{p}, b, validateFixture); e == nil {
		t.Fatal("busy accepted")
	}
	if _, e := os.Stat(out + ".lock"); e != nil {
		t.Fatal("broke foreign lock")
	}
	os.Remove(out + ".lock")
	alias := filepath.Join(t.TempDir(), "alias")
	if e := os.Symlink(p, alias); e == nil {
		if _, e = Publish(filepath.Join(alias, "record.json"), ip, []string{p}, b, validateFixture); e == nil {
			t.Fatal("journal parent alias accepted")
		}
	}
	if e := os.Symlink(ip, out); e == nil {
		if _, e = Publish(out, ip, nil, b, validateFixture); e == nil {
			t.Fatal("existing symlink replaced")
		}
		os.Remove(out)
	}
	if e := os.Link(ip, out); e == nil {
		if _, e = Publish(out, ip, nil, b, validateFixture); e == nil {
			t.Fatal("existing hardlink replaced")
		}
	}
}
func TestPublishFailureHonestyAndCleanup(t *testing.T) {
	for _, point := range []string{"write", "sync", "close", "publish", "directory-sync", "read-back", "cleanup-temp", "cleanup-lock"} {
		t.Run(point, func(t *testing.T) {
			d, ip, p, q := collectFixture(t)
			b, _ := Marshal(d)
			out := filepath.Join(t.TempDir(), "record.json")
			r, e := publish(out, ip, []string{p, q}, b, validateFixture, nil, func(s string) error {
				if s == point {
					return errors.New("injected secret must not escape")
				}
				return nil
			})
			if e == nil {
				t.Fatal("failure hidden")
			}
			published := point == "directory-sync" || point == "read-back" || point == "cleanup-temp" || point == "cleanup-lock"
			if r.OutputMayExist != published || r.Output != nil {
				t.Fatal("dishonest result", r, e)
			}
			_, statErr := os.Stat(out)
			if (statErr == nil) != published {
				t.Fatal("published final deleted or phantom publication")
			}
			entries, _ := os.ReadDir(filepath.Dir(out))
			for _, ent := range entries {
				if ent.Name() != "record.json" {
					t.Fatal("owned entry leaked", ent.Name())
				}
			}
		})
	}
}
func TestPublishNoReplaceAtPublication(t *testing.T) {
	d, ip, _, _ := collectFixture(t)
	b, _ := Marshal(d)
	out := filepath.Join(t.TempDir(), "record.json")
	r, e := publish(out, ip, nil, b, validateFixture, nil, func(point string) error {
		if point == "publish" {
			return os.WriteFile(out, []byte("other writer"), 0600)
		}
		return nil
	})
	if e == nil || r.OutputMayExist {
		t.Fatal("race overwritten", r, e)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "other writer" {
		t.Fatal("changed uncooperative writer output")
	}
}

func TestPublishActualLockCleanupFailurePreservesFinal(t *testing.T) {
	d, ip, _, _ := collectFixture(t)
	b, _ := Marshal(d)
	out := filepath.Join(t.TempDir(), "record.json")
	r, e := publish(out, ip, nil, b, validateFixture, nil, func(point string) error {
		if point == "read-back" {
			return os.WriteFile(filepath.Join(out+".lock", "obstruction"), nil, 0600)
		}
		return nil
	})
	if e == nil || !r.OutputMayExist || r.Output != nil {
		t.Fatal("actual cleanup failure hidden", r, e)
	}
	if _, e = os.Stat(out); e != nil {
		t.Fatal("final removed on cleanup failure")
	}
	if _, e = os.Stat(filepath.Join(out+".lock", "obstruction")); e != nil {
		t.Fatal("removed foreign obstruction")
	}
}

func TestPublishRefusesPhysicalJournalAliases(t *testing.T) {
	for _, suffix := range []string{"journal/record.json", "JOURNAL/nested/record.json", "journal.lock", "journal.LOCK"} {
		t.Run(suffix, func(t *testing.T) {
			d, ip, p, _ := collectFixture(t)
			raw, e := Marshal(d)
			if e != nil {
				t.Fatal(e)
			}
			root := filepath.Join(filepath.Dir(p), "Journal")
			if e = os.Rename(p, root); e != nil {
				t.Fatal(e)
			}
			if _, e = os.Stat(filepath.Join(filepath.Dir(root), "journal")); e != nil {
				t.Skip("case-sensitive filesystem")
			}
			if e = os.Mkdir(filepath.Join(root, "nested"), 0700); e != nil {
				t.Fatal(e)
			}
			before, e := os.ReadDir(root)
			if e != nil {
				t.Fatal(e)
			}
			out := filepath.Join(filepath.Dir(root), filepath.FromSlash(suffix))
			r, e := Publish(out, ip, []string{root}, raw, validateFixture)
			if e == nil || r.OutputMayExist {
				t.Fatalf("physical source namespace modified: %+v %v", r, e)
			}
			after, _ := os.ReadDir(root)
			if len(before) != len(after) {
				t.Fatal("journal entries changed")
			}
			for n := range before {
				if before[n].Name() != after[n].Name() {
					t.Fatal("journal entries changed")
				}
			}
			if _, e = os.Lstat(root + ".lock"); !os.IsNotExist(e) {
				t.Fatal("journal lock namespace changed", e)
			}
		})
	}
}
func TestPublishKeepsDistinctCaseSensitiveDirectory(t *testing.T) {
	d, ip, p, _ := collectFixture(t)
	raw, _ := Marshal(d)
	root := filepath.Join(filepath.Dir(p), "Journal")
	os.Rename(p, root)
	other := filepath.Join(filepath.Dir(p), "journal")
	if e := os.Mkdir(other, 0700); e != nil {
		t.Skip("case-insensitive filesystem")
	}
	out := filepath.Join(other, "record.json")
	if _, e := Publish(out, ip, []string{root}, raw, validateFixture); e != nil {
		t.Fatal("distinct case-sensitive directory refused", e)
	}
}
