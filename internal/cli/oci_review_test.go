package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/evidence"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestReviewLegacyDTrackLargeIntentRemainsReadable(t *testing.T) {
	ip, cfg := deliveryFixture(t, "https://unused.invalid")
	c, v, d, _, e := singlePreflight(cfg, ip, false)
	if e != nil {
		t.Fatal(e)
	}
	refs := make([]delivery.PayloadRef, 1500)
	for i := range refs {
		refs[i] = v.Payloads()[0].Ref()
	}
	intent := record.Intent{RioVersion: "test", Source: v.Source(), Payloads: refs, Binding: "security", Destination: d, ConfigSHA256: c.SHA256}
	data, _ := json.Marshal(intent)
	event := record.Event{SchemaVersion: 1, Sequence: 0, AttemptID: strings.Repeat("a", 32), ObservedAt: "2026-09-24T12:00:00Z", Kind: "intent", Data: data}
	raw, _ := json.MarshalIndent(event, "", "  ")
	raw = append(raw, '\n')
	if int64(len(raw)) >= record.EventLimit {
		t.Fatal("fixture exceeds existing byte contract")
	}
	dir := filepath.Join(t.TempDir(), "legacy")
	os.Mkdir(dir, 0700)
	eventPath := filepath.Join(dir, "00000000000000000000.json")
	os.WriteFile(eventPath, raw, 0600)
	var out, stderr bytes.Buffer
	if code := Main([]string{"delivery", "inspect", "--record", dir, "--json"}, &out, &stderr); code != 0 {
		t.Fatalf("legacy byte-valid journal refused: %d %s", code, stderr.String())
	}
	after, _ := os.ReadFile(eventPath)
	if !bytes.Equal(raw, after) {
		t.Fatal("legacy bytes changed")
	}
	doc, e := evidence.Collect(ip, []string{dir}, "test", validateSnapshot, recordPolicy)
	if e != nil {
		t.Fatal("legacy collection refused", e)
	}
	encoded, e := evidence.Marshal(doc)
	if e != nil {
		t.Fatal(e)
	}
	os.RemoveAll(dir)
	os.RemoveAll(filepath.Dir(ip))
	if _, e = evidence.Parse(encoded, validateSnapshot, recordPolicy); e != nil {
		t.Fatal("portable legacy inspection refused", e)
	}
}
func TestReviewMixedBatchFormerStructuralBoundary(t *testing.T) {
	for _, count := range []int{9932, 9933, 9934} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var posts, gets atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == "POST" {
					posts.Add(1)
					r.ParseMultipartForm(1 << 20)
					fmt.Fprint(w, `{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}`)
				} else {
					gets.Add(1)
					w.WriteHeader(500)
					fmt.Fprint(w, `{"errors":[{"code":"UNSUPPORTED"}]}`)
				}
			}))
			defer s.Close()
			ip, cfg := deliveryFixture(t, s.URL)
			origins := make([]string, count)
			for i := range origins {
				origins[i] = fmt.Sprintf("https://t%05d.invalid", i)
			}
			root := map[string]any{"version": 1, "artifacts": []any{map[string]any{"id": "app", "sbom": "bom.json"}}, "delivery": map[string]any{"targets": map[string]any{"a-security": map[string]any{"type": "dependency-track", "url": s.URL, "allowHTTP": true}, "z-registry": map[string]any{"type": "oci", "registry": strings.TrimPrefix(s.URL, "http://"), "repository": "demo/app", "allowHTTP": true, "auth": map[string]any{"anonymous": true}, "tokenServiceOrigins": origins}}}}
			raw, _ := json.Marshal(root)
			os.WriteFile(cfg, raw, 0600)
			t.Setenv("DTRACK_API_KEY", "synthetic-review-key")
			code, result, _ := runBatch(t, "deliver", "--index", ip, "--manifest", cfg)
			if code != 4 || posts.Load() != 1 || gets.Load() != 1 {
				t.Fatalf("valid complete envelopes diverged: exit%d posts%d gets%d", code, posts.Load(), gets.Load())
			}
			items := result["items"].([]any)
			for _, item := range items {
				path := item.(map[string]any)["record"].(string)
				snap, e := record.Read(path)
				if e != nil || len(snap.Events) != 2 {
					t.Fatal("preflight allowed unreadable intent", e)
				}
				if e = validateSnapshot(snap); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}
