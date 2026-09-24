package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/delivery/runner"
)

func TestObserveHashesBytesAndNeverWrites(t *testing.T) {
	for _, mode := range []string{"valid", "manifest", "config", "blob", "missing-blob", "tag", "subject", "missing-subject", "missing-discovery"} {
		t.Run(mode, func(t *testing.T) {
			s := newRegistry(t)
			v, path := verified(t)
			subject := s.seedSubject()
			c := submitClient(t, s, v, &subject)
			if _, e := c.Submit(context.Background(), v.Payloads()); e != nil {
				t.Fatal(e)
			}
			os.RemoveAll(filepath.Dir(path))
			s.mu.Lock()
			switch mode {
			case "manifest":
				s.mapManifest[c.options.Publication.Manifest.Digest][2] = 'X'
			case "config":
				s.blobs[c.options.Publication.Config.Digest] = []byte("{]")
			case "blob":
				s.blobs["sha256:"+v.Source().OutputSHA256][0] = '['
			case "missing-blob":
				delete(s.blobs, "sha256:"+v.Source().OutputSHA256)
			case "tag":
				raw := []byte(`{"schemaVersion":2}`)
				dg := "sha256:" + delivery.Digest(raw)
				s.mapManifest[dg] = raw
				s.tags[c.options.Publication.Tag] = dg
			case "subject":
				s.mapManifest[subject.Digest][2] = 'X'
			case "missing-subject":
				delete(s.mapManifest, subject.Digest)
			case "missing-discovery":
				s.noReferrers = true
			}
			before := len(s.writes)
			s.mu.Unlock()
			o, e := c.Observe(context.Background(), expected(c.options))
			s.mu.Lock()
			defer s.mu.Unlock()
			if len(s.writes) != before {
				t.Fatal("reconcile wrote")
			}
			if mode == "valid" {
				if e != nil || o.Value != "verified" {
					t.Fatal(o, e)
				}
			} else if e == nil || o.Value == "verified" {
				t.Fatal("mismatch accepted", mode, o, e)
			}
			if mode == "tag" && o.Code != "tag_drift" {
				t.Fatal(o)
			}
		})
	}
}
func TestObserveReferrersPagination(t *testing.T) {
	for _, mode := range []string{"found", "missing", "duplicate", "escape", "pages"} {
		t.Run(mode, func(t *testing.T) {
			s := newRegistry(t)
			v, _ := verified(t)
			subject := s.seedSubject()
			c := submitClient(t, s, v, &subject)
			if _, e := c.Submit(context.Background(), v.Payloads()); e != nil {
				t.Fatal(e)
			}
			original := s.server.Config.Handler
			s.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.Contains(r.URL.Path, "/referrers/") {
					original.ServeHTTP(w, r)
					return
				}
				w.Header().Set("Content-Type", IndexMediaType)
				page := r.URL.Query().Get("page")
				want := referrer{MediaType: ManifestMediaType, Digest: c.options.Publication.Manifest.Digest, Size: c.options.Publication.Manifest.Size, ArtifactType: SBOMMediaType}
				refs := []referrer{}
				switch mode {
				case "found":
					if page == "2" {
						refs = append(refs, want)
					} else {
						w.Header().Set("Link", `<?page=2>; rel="next"`)
					}
				case "duplicate":
					refs = append(refs, want, want)
				case "escape":
					w.Header().Set("Link", `<https://unapproved.invalid/escape>; rel="next"`)
				case "pages":
					n := 1
					fmt.Sscanf(page, "%d", &n)
					w.Header().Set("Link", fmt.Sprintf(`<?page=%d>; rel="next"`, n+1))
				}
				json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 2, "mediaType": IndexMediaType, "manifests": refs})
			})
			o, e := c.Observe(context.Background(), expected(c.options))
			if mode == "found" {
				if e != nil || o.Value != "verified" {
					t.Fatal(o, e)
				}
			} else if e == nil || o.Value == "verified" {
				t.Fatal(mode, o, e)
			}
			if mode == "pages" && o.Code != "referrers_limit" {
				t.Fatal(o)
			}
		})
	}
}
func TestObserveReferrersPreallocationBounds(t *testing.T) {
	want := Descriptor{ManifestMediaType, "sha256:" + strings.Repeat("a", 64), 1}
	seen := map[string]bool{}
	total := 10000
	raw := []byte(`{"schemaVersion":2,"manifests":[not-even-json]}`)
	if _, e := parseReferrers(raw, want, &total, seen); e == nil || !strings.Contains(e.Error(), "referrers_limit") {
		t.Fatal("excess element decoded", e)
	}
	// A descriptor's unknown array must be refused before allocating its values.
	raw = []byte(`{"schemaVersion":2,"manifests":[{"unknown":[` + strings.Repeat(`{},`, 300000) + `{}]}]}`)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	total = 0
	_, e := parseReferrers(raw, want, &total, map[string]bool{})
	runtime.ReadMemStats(&after)
	if e == nil {
		t.Fatal("unknown descriptor accepted")
	}
	if after.TotalAlloc-before.TotalAlloc > 4<<20 {
		t.Fatalf("descriptor materialized before shape refusal: %d bytes", after.TotalAlloc-before.TotalAlloc)
	}
}

type crashAfterAccepted struct{ client *client }

func (c crashAfterAccepted) Submit(ctx context.Context, payloads []delivery.Payload) (delivery.Submission, error) {
	sub, e := c.client.Submit(ctx, payloads)
	if e == nil && sub.Disposition == "accepted" {
		os.Exit(73)
	}
	return sub, e
}
func TestCrashOCIIntentOnlyRecovery(t *testing.T) {
	if os.Getenv("RIO_OCI_CRASH_CHILD") == "1" {
		v, e := delivery.Verify(os.Getenv("RIO_OCI_CRASH_INDEX"), "app", false)
		if e != nil {
			t.Fatal(e)
		}
		d := clientDescription(t, os.Getenv("RIO_OCI_CRASH_URL"), "{anonymous: true}", "")
		p, e := (Provider{}).Prepare(d, v.Source(), []delivery.PayloadRef{v.Payloads()[0].Ref()})
		if e != nil {
			t.Fatal(e)
		}
		p.Description.DestinationName = "registry"
		c := buildClient(t, p.Description)
		_, e = runner.Submit(context.Background(), runner.Prepared{Verified: v, Description: p.Description, ExpectedReferences: p.ExpectedReferences, ValidateIntent: ValidateIntent, Intent: record.Intent{RioVersion: "test", Binding: "registry", ConfigSHA256: strings.Repeat("a", 64)}, Target: crashAfterAccepted{c}}, os.Getenv("RIO_OCI_CRASH_JOURNAL"))
		t.Fatalf("child did not crash: %v", e)
	}
	s := newRegistry(t)
	v, path := verified(t)
	journal := filepath.Join(t.TempDir(), "journal")
	s.mu.Lock()
	s.intentPath = journal
	s.mu.Unlock()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(exe, "-test.run=^TestCrashOCIIntentOnlyRecovery$")
	cmd.Env = append(os.Environ(), "RIO_OCI_CRASH_CHILD=1", "RIO_OCI_CRASH_INDEX="+filepath.Join(filepath.Dir(path), "index.json"), "RIO_OCI_CRASH_URL="+s.server.URL, "RIO_OCI_CRASH_JOURNAL="+journal)
	output, e := cmd.CombinedOutput()
	if exit, ok := e.(*exec.ExitError); !ok || exit.ExitCode() != 73 {
		t.Fatalf("unexpected child result %v: %s", e, output)
	}
	if _, e = record.Read(journal); e == nil {
		t.Fatal("crash lock silently broken")
	}
	if e = os.Remove(journal + ".lock"); e != nil {
		t.Fatal(e)
	} // child has actually exited; explicit owned stale-lock cleanup.
	snap, e := record.Read(journal)
	if e != nil || len(snap.Events) != 1 || snap.Disposition != "unknown" {
		t.Fatal(snap, e)
	}
	rawIntent, _ := os.ReadFile(filepath.Join(journal, "00000000000000000000.json"))
	os.RemoveAll(filepath.Dir(path))
	target, e := (Provider{}).Build(snap.Intent.Destination, func(string) (string, bool) { t.Fatal("anonymous recovery resolved secret"); return "", false })
	if e != nil {
		t.Fatal(e)
	}
	w, e := record.Open(journal)
	if e != nil {
		t.Fatal(e)
	}
	r, e := runner.Reconcile(context.Background(), w, target.(delivery.Observer), snap.Intent.ConfigSHA256, 0)
	if closeErr := w.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if e != nil || r.Acknowledgment != "unknown" || r.Verification != "verified" {
		t.Fatal(r, e)
	}
	s.mu.Lock()
	writes := len(s.writes)
	requests := len(s.requests)
	s.mu.Unlock()
	r, e = runner.Submit(context.Background(), runner.Prepared{Verified: v, Description: snap.Intent.Destination, ExpectedReferences: snap.Intent.ExpectedReferences, ValidateIntent: ValidateIntent, Intent: snap.Intent, Target: target}, journal)
	if e == nil || r.ExitCode != 2 {
		t.Fatal("old journal reused", r, e)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.writes) != writes || len(s.requests) != requests {
		t.Fatal("reuse made request")
	}
	after, _ := os.ReadFile(filepath.Join(journal, "00000000000000000000.json"))
	if string(after) != string(rawIntent) {
		t.Fatal("intent rewritten")
	}
}
