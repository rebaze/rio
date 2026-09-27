package batchrecord

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/index"
)

func fixture(t *testing.T) (Descriptor, []byte) {
	t.Helper()
	idx := index.New("test", index.FileRef{Path: "rio.yaml", SHA256: delivery.Digest([]byte("normalization manifest"))})
	for _, id := range []string{"app", "worker"} {
		sha := delivery.Digest([]byte(id))
		idx.Artifacts = append(idx.Artifacts, index.Artifact{ID: id, Input: index.FileRef{Path: id + ".json", SHA256: sha}, Output: index.FileRef{Path: id + ".cdx.json", SHA256: sha}, SpecVersion: index.SpecVersions{Input: "1.6", Output: "1.6"}, Gate: index.GateOK})
	}
	raw, err := index.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	d := Descriptor{SchemaVersion: 1, Kind: "rio-delivery-batch", Index: File{PathHint: "record.json.index.json", SHA256: delivery.Digest(raw)}, NormalizationManifestSHA256: idx.Manifest.SHA256, DeliveryManifestSHA256: delivery.Digest([]byte("delivery manifest")), CompletionPathHint: "record.json.batch-result.json", ArtifactIDs: []string{"app", "worker"}, Scope: delivery.BatchScope{ArtifactFilter: []string{}, TargetFilter: []string{}, Targets: []delivery.BatchTarget{{Name: "security", Exclude: []string{}}, {Name: "archive", Exclude: []string{"worker"}}}}, Pairs: []Pair{}}
	for _, route := range [][2]string{{"app", "archive"}, {"app", "security"}, {"worker", "security"}} {
		sha := delivery.Digest([]byte(route[0]))
		identity, _ := json.Marshal(route)
		intent := record.Intent{RioVersion: "test", Binding: route[1], ConfigSHA256: d.DeliveryManifestSHA256, Source: delivery.Source{IndexSHA256: d.Index.SHA256, ArtifactID: route[0], OutputSHA256: sha, Gate: "ok"}, Destination: delivery.Description{Type: "test", DestinationName: route[1], Identity: identity, Options: json.RawMessage(`{}`), CredentialRefs: []string{}, Capabilities: []string{"submit"}}, Payloads: []delivery.PayloadRef{{Role: "sbom", MediaType: "application/vnd.cyclonedx+json", SHA256: sha, Size: 4, SourceSHA256: sha, Transformation: "identity"}}}
		// Destination identity is an object, as required by the journal contract.
		intent.Destination.Identity = json.RawMessage(`{"route":` + string(identity) + `}`)
		d.Pairs = append(d.Pairs, Pair{AttemptID: fmt.Sprintf("%032x", len(d.Pairs)+1), ID: delivery.PairKey(intent.Source, intent.Destination), ArtifactID: route[0], Target: route[1], JournalPathHint: route[0] + "-" + route[1], Intent: intent})
	}
	return d, raw
}

func TestDescriptorScopeAndBindings(t *testing.T) {
	d, raw := fixture(t)
	if err := ValidateIndex(d, raw); err != nil {
		t.Fatal(err)
	}
	b, err := MarshalDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseDescriptor(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Pairs) != 3 || parsed.NormalizationManifestSHA256 == parsed.DeliveryManifestSHA256 {
		t.Fatal("scope or distinct manifests lost")
	}
	for _, kind := range []string{"missing-pair", "wrong-key", "filtered-pair", "different-index", "policy-binding"} {
		t.Run(kind, func(t *testing.T) {
			x, _ := ParseDescriptor(b)
			source := raw
			switch kind {
			case "missing-pair":
				x.Pairs = x.Pairs[:2]
			case "wrong-key":
				x.Pairs[0].ID = strings.Repeat("a", 64)
			case "filtered-pair":
				x.Scope.TargetFilter = []string{"security"}
			case "different-index":
				source = append(append([]byte{}, raw...), '\n')
			case "policy-binding":
				x.Pairs[0].Intent.Source.AllowFailedGate = true
			}
			if err := ValidateIndex(x, source); err == nil {
				t.Fatal("inconsistent scope accepted")
			}
		})
	}
}

func TestCompletionKeepsUnattemptedAndRefusesReceiptContradiction(t *testing.T) {
	d, _ := fixture(t)
	raw, err := MarshalDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	c := Completion{SchemaVersion: 1, Kind: "rio-delivery-batch-result", BatchSHA256: delivery.Digest(raw), Outcome: "partial", RequestMayHaveOccurred: true, Items: []CompletionItem{}}
	for i, p := range d.Pairs {
		item := CompletionItem{PairID: p.ID, State: "unattempted"}
		if i == 0 {
			item.State = "accepted"
			item.AttemptID = p.AttemptID
			item.Acknowledgment = "accepted"
			item.RequestMayHaveOccurred = true
		}
		if i == 1 {
			item.State = "unknown"
			item.AttemptID = p.AttemptID
			item.Acknowledgment = "unknown"
			item.RequestMayHaveOccurred = true
			item.ErrorCode = "remote_unknown"
		}
		c.Items = append(c.Items, item)
	}
	rawC, err := MarshalCompletion(c, d, raw)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCompletion(rawC, d, raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Items[2].State != "unattempted" {
		t.Fatal("suffix outcome lost")
	}
	c.Items[2].RequestMayHaveOccurred = true
	if _, err = MarshalCompletion(c, d, raw); err == nil {
		t.Fatal("unattempted request accepted")
	}
	// A committed journal acknowledgment is authoritative, not a runner assertion.
	snapshot := record.Snapshot{Events: []record.Event{{Kind: "intent", AttemptID: d.Pairs[0].AttemptID}, {Kind: "submission", AttemptID: d.Pairs[0].AttemptID}}, Disposition: "rejected"}
	if err = CheckCompletionJournal(parsed.Items[0], snapshot); err == nil {
		t.Fatal("receipt contradiction accepted")
	}
}

func TestImmutableSourcesAndReservation(t *testing.T) {
	dir := t.TempDir()
	d, raw := fixture(t)
	ip := filepath.Join(dir, "index.json")
	os.WriteFile(ip, raw, 0600)
	out := filepath.Join(dir, "record.json")
	r, err := Reserve(out, ip, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := Reserve(out, ip, nil); err == nil {
		t.Fatal("duplicate reservation accepted")
	}
	d.Index.PathHint = r.Paths.Index
	d.CompletionPathHint = r.Paths.Completion
	descriptor, err := MarshalDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.PublishSources(raw, descriptor); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(ip, []byte(`{}`), 0600)
	got, err := os.ReadFile(r.Paths.Index)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("snapshot mutable", err)
	}
	if err = r.PublishSources(raw, descriptor); err == nil {
		t.Fatal("existing sources replaced")
	}
	if _, err = os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("sources falsely publish final record")
	}
}

func TestReservationRefusesSourceJournalAndSymlinkCollisions(t *testing.T) {
	for _, kind := range []string{"index", "journal", "journal-lock", "existing", "symlink", "source-existing"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			ip := filepath.Join(dir, "index.json")
			os.WriteFile(ip, []byte(`{}`), 0600)
			journal := filepath.Join(dir, "journal")
			out := filepath.Join(dir, "record.json")
			switch kind {
			case "index":
				out = ip
			case "journal":
				out = journal
			case "journal-lock":
				out = journal + ".lock"
			case "existing":
				os.WriteFile(out, []byte("keep"), 0600)
			case "symlink":
				if err := os.Symlink(ip, out); err != nil {
					t.Skip("symlink unavailable")
				}
			case "source-existing":
				os.WriteFile(out+".batch.json", []byte("keep"), 0600)
			}
			if r, err := Reserve(out, ip, []string{journal}); err == nil {
				r.Close()
				t.Fatal("collision accepted")
			}
		})
	}
}

func TestExplicitUnknownReceiptCannotBeOverridden(t *testing.T) {
	item := CompletionItem{State: "accepted", AttemptID: strings.Repeat("1", 32), Acknowledgment: "accepted", RequestMayHaveOccurred: true}
	s := record.Snapshot{Events: []record.Event{{Kind: "intent", AttemptID: item.AttemptID}, {Kind: "submission", AttemptID: item.AttemptID}}, Disposition: "unknown"}
	if err := CheckCompletionJournal(item, s); err == nil {
		t.Fatal("runner assertion overrode committed unknown acknowledgment")
	}
	s.Events = s.Events[:1]
	if err := CheckCompletionJournal(item, s); err != nil {
		t.Fatal("intent-only history must retain separate runner assertion", err)
	}
}

func TestDescriptorLimitsAndStoreFailures(t *testing.T) {
	d, raw := fixture(t)
	b, err := MarshalDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseDescriptor(bytes.Repeat([]byte(" "), int(SourceLimit)+1)); err == nil {
		t.Fatal("oversized source accepted")
	}
	object := map[string]json.RawMessage{}
	json.Unmarshal(b, &object)
	pairs := []json.RawMessage{}
	one, _ := json.Marshal(d.Pairs[0])
	for i := 0; i < 1025; i++ {
		pairs = append(pairs, one)
	}
	object["pairs"], _ = json.Marshal(pairs)
	excess, _ := json.Marshal(object)
	if _, err := ParseDescriptor(excess); err == nil || !strings.Contains(err.Error(), "size_limit") {
		t.Fatal("1025 pairs must refuse before retaining them", err)
	}
	for _, point := range []string{"write", "sync", "publish", "directory-sync", "read-back"} {
		t.Run(point, func(t *testing.T) {
			dir := t.TempDir()
			ip := filepath.Join(dir, "index.json")
			os.WriteFile(ip, raw, 0600)
			r, err := Reserve(filepath.Join(dir, "record.json"), ip, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			r.fail = func(at string) error {
				if at == point {
					return os.ErrPermission
				}
				return nil
			}
			may, err := r.Publish(r.Paths.Output, []byte("safe"), 100, nil)
			if err == nil {
				t.Fatal("injected persistence error ignored")
			}
			wantMay := point == "directory-sync" || point == "read-back"
			if may != wantMay {
				t.Fatal("wrong presence claim", point, may)
			}
			if wantMay {
				got, _ := os.ReadFile(r.Paths.Output)
				if string(got) != "safe" {
					t.Fatal("published data changed")
				}
			}
		})
	}
}

func TestCompletionRetainsAcceptedButUnpersistedFinalAttempt(t *testing.T) {
	d, _ := fixture(t)
	raw, err := MarshalDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	c := Completion{SchemaVersion: 1, Kind: "rio-delivery-batch-result", BatchSHA256: delivery.Digest(raw), Outcome: "partial", RequestMayHaveOccurred: true, ErrorCode: "persistence_failed", Items: []CompletionItem{}}
	for _, p := range d.Pairs {
		c.Items = append(c.Items, CompletionItem{PairID: p.ID, State: "accepted", AttemptID: p.AttemptID, Acknowledgment: "accepted", RequestMayHaveOccurred: true})
	}
	c.Items[2].ErrorCode = "persistence_failed"
	if _, err := MarshalCompletion(c, d, raw); err != nil {
		t.Fatal("runner assertion after failed journal persistence lost", err)
	}
}

func TestCompletionNoRequestCannotContradictCommittedSubmission(t *testing.T) {
	item := CompletionItem{State: "error", AttemptID: strings.Repeat("1", 32)}
	s := record.Snapshot{Events: []record.Event{{Kind: "intent", AttemptID: item.AttemptID}, {Kind: "submission", AttemptID: item.AttemptID}}, Disposition: "unknown"}
	if err := CheckCompletionJournal(item, s); err == nil {
		t.Fatal("no-request claim contradicts captured submission")
	}
}

func TestRacingOutputIsNeverReplacedAndPresenceIsReported(t *testing.T) {
	dir := t.TempDir()
	ip := filepath.Join(dir, "index.json")
	os.WriteFile(ip, []byte(`{}`), 0600)
	r, err := Reserve(filepath.Join(dir, "record.json"), ip, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.fail = func(point string) error {
		if point == "publish" {
			if err := os.WriteFile(r.Paths.Output, []byte("other creator"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}
	may, err := r.Publish(r.Paths.Output, []byte("ours"), 100, nil)
	if err == nil || !may {
		t.Fatal("racing existing output presence lost", may, err)
	}
	got, _ := os.ReadFile(r.Paths.Output)
	if string(got) != "other creator" {
		t.Fatal("replaced racing output")
	}
}

func TestDescriptorAllows1024SelectedPairs(t *testing.T) {
	d, raw := fixture(t)
	seed := d.Pairs[0]
	d.Pairs = []Pair{}
	d.Scope.Targets = []delivery.BatchTarget{}
	for i := 0; i < 1024; i++ {
		p := seed
		p.Target = fmt.Sprintf("target-%04d", i)
		p.AttemptID = fmt.Sprintf("%032x", i+1)
		p.JournalPathHint = p.Target
		p.Intent.Binding = p.Target
		p.Intent.Destination.DestinationName = p.Target
		p.Intent.Destination.Identity = json.RawMessage(fmt.Sprintf(`{"target":%q}`, p.Target))
		p.ID = delivery.PairKey(p.Intent.Source, p.Intent.Destination)
		d.Pairs = append(d.Pairs, p)
		d.Scope.Targets = append(d.Scope.Targets, delivery.BatchTarget{Name: p.Target, Exclude: []string{"worker"}})
	}
	if err := ValidateIndex(d, raw); err != nil {
		t.Fatal(err)
	}
	b, err := MarshalDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseDescriptor(b); err != nil {
		t.Fatal(err)
	}
}

func TestCompletionRetainsLaterPreflightFailureWithNoRequests(t *testing.T) {
	d, _ := fixture(t)
	raw, err := MarshalDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	c := Completion{SchemaVersion: 1, Kind: "rio-delivery-batch-result", BatchSHA256: delivery.Digest(raw), Outcome: "error", ErrorCode: "invalid_record", Items: []CompletionItem{}}
	for _, p := range d.Pairs {
		c.Items = append(c.Items, CompletionItem{PairID: p.ID, State: "unattempted"})
	}
	c.Items[1].State = "error"
	c.Items[1].ErrorCode = "invalid_record"
	if _, err := MarshalCompletion(c, d, raw); err != nil {
		t.Fatal("ordinary preflight outcome lost", err)
	}
}
