package runner

import (
	"context"
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/index"
	"os"
	"path/filepath"
	"testing"
)

func prepared(t *testing.T, path string, fail bool) Prepared {
	t.Helper()
	dir := t.TempDir()
	b := []byte(`{"bomFormat":"CycloneDX","metadata":{"component":{"name":"app","version":"1"}}}`)
	os.WriteFile(filepath.Join(dir, "bom.json"), b, 0600)
	h := delivery.Digest(b)
	idx := index.New("test", index.FileRef{Path: "rio.yaml", SHA256: h})
	idx.Artifacts = []index.Artifact{{ID: "app", Input: index.FileRef{Path: "bom.json", SHA256: h}, Output: index.FileRef{Path: "bom.json", SHA256: h}, SpecVersion: index.SpecVersions{Input: "1.6", Output: "1.6"}, Gate: index.GateOK}}
	index.Write(dir, idx)
	v, e := delivery.Verify(filepath.Join(dir, "index.json"), "app", false)
	if e != nil {
		t.Fatal(e)
	}
	d := delivery.Description{Type: "test", DestinationName: "test", Identity: json.RawMessage(`{"object":"a"}`), Options: json.RawMessage(`{}`), CredentialRefs: []string{}, Capabilities: []string{"submit"}}
	target := &fakeTarget{t: t, path: path, fail: fail}
	return Prepared{Verified: v, Description: d, Intent: record.Intent{RioVersion: "test", Binding: "test", ConfigSHA256: h}, Target: target}
}

type fakeTarget struct {
	t     *testing.T
	path  string
	fail  bool
	calls int
}

func (f *fakeTarget) Submit(ctx context.Context, p []delivery.Payload) (delivery.Submission, error) {
	f.calls++
	if _, e := os.Stat(filepath.Join(f.path, "00000000000000000000.json")); e != nil {
		f.t.Fatal("HTTP before intent")
	}
	if _, e := record.Read(f.path); e == nil {
		f.t.Fatal("lock not held during request")
	}
	if f.fail {
		os.Mkdir(filepath.Join(f.path, "unexpected"), 0700)
	}
	return delivery.Submission{Disposition: "accepted", References: []delivery.Reference{}, Observations: []delivery.Observation{{Kind: "acknowledgment", Value: "accepted", Origin: "receiver", Code: "accepted", References: []delivery.Reference{}}}}, nil
}
func TestSubmitOrdering(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "save failure"}[fail], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "journal")
			p := prepared(t, path, fail)
			r, e := Submit(context.Background(), p, path)
			if p.Target.(*fakeTarget).calls != 1 || r.Outcome != "accepted" || !r.RequestMayHaveOccurred {
				t.Fatal(r, e)
			}
			if fail {
				if r.ExitCode != 3 || e == nil {
					t.Fatal(r, e)
				}
			} else {
				if e != nil || r.ExitCode != 0 {
					t.Fatal(r, e)
				}
				r, e = Submit(context.Background(), p, path)
				if r.ExitCode != 2 || e == nil || p.Target.(*fakeTarget).calls != 1 {
					t.Fatal("reused journal", r, e)
				}
			}
		})
	}
}
func TestSubmitBusy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	os.Mkdir(path+".lock", 0700)
	p := prepared(t, path, false)
	r, e := Submit(context.Background(), p, path)
	if r.ExitCode != 2 || e == nil || p.Target.(*fakeTarget).calls != 0 {
		t.Fatal(r, e)
	}
}
