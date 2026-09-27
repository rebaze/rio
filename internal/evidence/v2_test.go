package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/batchrecord"
	"github.com/rebaze/rio/internal/delivery/record"
)

func batchFixture(t *testing.T) (string, string, batchrecord.Descriptor) {
	t.Helper()
	ip, _, _ := fixture(t)
	raw, _ := os.ReadFile(ip)
	root := filepath.Dir(ip)
	intent := fixtureIntent(raw)
	intent.Binding = "security"
	journal := filepath.Join(root, "bound-journal")
	w, err := record.Create(journal, intent)
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := json.Marshal(delivery.Submission{Disposition: "accepted", References: []delivery.Reference{}, Observations: []delivery.Observation{{Kind: "acknowledgment", Value: "accepted", Origin: "receiver", Code: "upload_response", References: []delivery.Reference{}}}})
	if err = w.Append("submission", sub); err != nil {
		t.Fatal(err)
	}
	w.Close()
	snapshot, err := record.Read(journal)
	if err != nil {
		t.Fatal(err)
	}
	d := batchrecord.Descriptor{SchemaVersion: 1, Kind: "rio-delivery-batch", Index: batchrecord.File{PathHint: "index.json", SHA256: delivery.Digest(raw)}, NormalizationManifestSHA256: strings.Repeat("a", 64), DeliveryManifestSHA256: intent.ConfigSHA256, CompletionPathHint: "completion.json", ArtifactIDs: []string{"app", "without"}, Scope: delivery.BatchScope{ArtifactFilter: []string{}, TargetFilter: []string{}, Targets: []delivery.BatchTarget{{Name: "security", Exclude: []string{"without"}}, {Name: "archive", Exclude: []string{"without"}}}}, Pairs: []batchrecord.Pair{{ID: delivery.PairKey(intent.Source, intent.Destination), AttemptID: snapshot.Events[0].AttemptID, ArtifactID: "app", Target: "security", JournalPathHint: "bound-journal", Intent: intent}}}
	intent.Binding = "archive"
	intent.Destination.DestinationName = "archive"
	intent.Destination.Identity = json.RawMessage(`{"url":"https://unreachable.invalid","project":"mirror"}`)
	d.Pairs = append(d.Pairs, batchrecord.Pair{ID: delivery.PairKey(intent.Source, intent.Destination), AttemptID: strings.Repeat("b", 32), ArtifactID: "app", Target: "archive", JournalPathHint: "missing-journal", Intent: intent})
	b, err := batchrecord.MarshalDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	bp := filepath.Join(root, "batch.json")
	if err = os.WriteFile(bp, b, 0600); err != nil {
		t.Fatal(err)
	}
	return ip, bp, d
}

func TestV2RoundTripMissingScopeAndOfflineSources(t *testing.T) {
	_, bp, _ := batchFixture(t)
	d, err := CollectV2("", []string{bp}, nil, "collector", validateFixture)
	if err != nil {
		t.Fatal(err)
	}
	if d.SchemaVersion != 2 || d.ExpectedScope != "recorded" || len(d.Batches) != 1 || len(d.Deliveries) != 1 {
		t.Fatal("wrong v2 inventory", d)
	}
	pairs := d.Batches[0].Pairs
	if pairs[0].Acknowledgment != "accepted" || pairs[1].Evidence != "missing" || pairs[1].RunnerState != "not-recorded" {
		t.Fatal("missing/crash evidence misrepresented", pairs)
	}
	raw, err := Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(filepath.Dir(bp))
	parsed, err := Parse(raw, validateFixture)
	if err != nil {
		t.Fatal("offline inspect followed a source path", err)
	}
	again, err := Marshal(parsed)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("v2 round trip changed evidence", err)
	}
	for _, kind := range []string{"coverage", "repair-source", "receipt", "scope"} {
		t.Run(kind, func(t *testing.T) {
			var m map[string]any
			json.Unmarshal(raw, &m)
			switch kind {
			case "coverage":
				m["batches"].([]any)[0].(map[string]any)["pairs"].([]any)[1].(map[string]any)["evidence"] = "captured"
			case "repair-source":
				m["normalization"].(map[string]any)["index"].(map[string]any)["manifest"].(map[string]any)["sha256"] = strings.Repeat("b", 64)
			case "receipt":
				m["deliveries"].([]any)[0].(map[string]any)["summary"].(map[string]any)["acknowledgment"] = "rejected"
			case "scope":
				m["batches"].([]any)[0].(map[string]any)["scope"].(map[string]any)["artifactIDs"] = []string{"app"}
			}
			bad, _ := json.Marshal(m)
			if _, err := Parse(bad, validateFixture); err == nil {
				t.Fatal("edited readable facts accepted")
			}
		})
	}
}

func TestV2CompletionAndSelectionRefusals(t *testing.T) {
	ip, bp, desc := batchFixture(t)
	raw, _ := os.ReadFile(bp)
	c := batchrecord.Completion{SchemaVersion: 1, Kind: "rio-delivery-batch-result", BatchSHA256: delivery.Digest(raw), Outcome: "error", RequestMayHaveOccurred: true, ErrorCode: "persistence_failed", Items: []batchrecord.CompletionItem{{PairID: desc.Pairs[0].ID, AttemptID: desc.Pairs[0].AttemptID, State: "accepted", Acknowledgment: "accepted", RequestMayHaveOccurred: true, ErrorCode: "persistence_failed"}, {PairID: desc.Pairs[1].ID, State: "unattempted"}}}
	b, err := batchrecord.MarshalCompletion(c, desc, raw)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(filepath.Dir(bp), "completion.json"), b, 0600)
	d, err := CollectV2("", []string{bp}, nil, "test", validateFixture)
	if err != nil {
		t.Fatal(err)
	}
	if d.Batches[0].Pairs[1].RunnerState != "unattempted" || d.Batches[0].Pairs[1].Evidence != "missing" {
		t.Fatal(d.Batches[0])
	}
	if _, err = CollectV2(ip, []string{bp, bp}, nil, "test", validateFixture); err == nil {
		t.Fatal("duplicate batch accepted")
	}
	if _, err = CollectV2(ip, []string{bp}, []string{filepath.Join(filepath.Dir(bp), "bound-journal")}, "test", validateFixture); err == nil {
		t.Fatal("duplicate journal selection accepted")
	}
	c.Items[0].State = "rejected"
	c.Items[0].Acknowledgment = "rejected"
	c.Outcome = "rejected"
	b, err = batchrecord.MarshalCompletion(c, desc, raw)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(filepath.Dir(bp), "completion.json"), b, 0600)
	if _, err = CollectV2("", []string{bp}, nil, "test", validateFixture); err == nil {
		t.Fatal("completion overrode committed accepted receipt")
	}
}

func TestV2ExplicitJournalsHaveNoExpectedScope(t *testing.T) {
	ip, p, q := fixture(t)
	d, err := CollectV2(ip, nil, []string{p, q}, "test", validateFixture)
	if err != nil {
		t.Fatal(err)
	}
	if d.ExpectedScope != "not-recorded" || len(d.Batches) != 0 {
		t.Fatal("invented expected routing")
	}
	raw, err := Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Parse(raw, validateFixture); err != nil {
		t.Fatal(err)
	}
}

func TestV2JournalLimitIncludes257And1024(t *testing.T) {
	ip, p, _ := fixture(t)
	raw, _ := os.ReadFile(ip)
	seed, err := record.CaptureRead(p, SourceLimit)
	if err != nil {
		t.Fatal(err)
	}
	captures := []record.Capture{}
	for i := 0; i < 1025; i++ {
		events := [][]byte{}
		for _, source := range seed.RawEvents {
			var event record.Event
			if err = json.Unmarshal(source, &event); err != nil {
				t.Fatal(err)
			}
			event.AttemptID = fmt.Sprintf("%032x", i+1)
			b, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			events = append(events, b)
		}
		snapshot, err := record.DecodeEvents(events)
		if err != nil {
			t.Fatal(err)
		}
		captures = append(captures, record.Capture{Snapshot: snapshot, RawEvents: events})
	}
	for _, n := range []int{257, 1024} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			d, err := assembleV2(raw, captures[:n], nil, "test", validateFixture)
			if err != nil {
				t.Fatal(err)
			}
			b, err := Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := Parse(b, validateFixture)
			if err != nil || len(parsed.Deliveries) != n {
				t.Fatal("v2 boundary failed", err)
			}
		})
	}
	if _, err := assembleV2(raw, captures, nil, "test", validateFixture); err == nil {
		t.Fatal("1025 journals accepted")
	}
	if _, err := assemble(raw, captures[:257], "test", validateFixture); err == nil {
		t.Fatal("v1 limit silently widened")
	}
}

func TestV2LaterBatchCanUseAnOriginallyUnattemptedSlot(t *testing.T) {
	_, first, old := batchFixture(t)
	root := filepath.Dir(first)
	w, err := record.Create(filepath.Join(root, "missing-journal"), old.Pairs[1].Intent)
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	s, err := record.Read(filepath.Join(root, "missing-journal"))
	if err != nil {
		t.Fatal(err)
	}
	next := old
	next.Scope = old.Scope
	next.Scope.TargetFilter = []string{"archive"}
	next.Scope.ArtifactFilter = []string{"app"}
	next.CompletionPathHint = "later-completion.json"
	pair := old.Pairs[1]
	pair.AttemptID = s.Events[0].AttemptID
	next.Pairs = []batchrecord.Pair{pair}
	raw, err := batchrecord.MarshalDescriptor(next)
	if err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(root, "later-batch.json")
	os.WriteFile(second, raw, 0600)
	if _, err := CollectV2("", []string{first}, nil, "test", validateFixture); err == nil {
		t.Fatal("foreign attempt at a path hint silently joined without explicit selection")
	}
	d, err := CollectV2("", []string{first, second}, nil, "test", validateFixture)
	if err != nil {
		t.Fatal("explicit later compatible batch cannot be combined", err)
	}
	missing, captured := 0, 0
	for _, b := range d.Batches {
		for _, p := range b.Pairs {
			if p.Target == "archive" {
				if p.Evidence == "missing" {
					missing++
				} else {
					captured++
				}
			}
		}
	}
	if missing != 1 || captured != 1 {
		t.Fatal("later attempt rewrote original scope", d.Batches)
	}
	b, err := Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Parse(b, validateFixture); err != nil {
		t.Fatal(err)
	}
}
