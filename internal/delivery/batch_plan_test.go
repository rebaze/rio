package delivery

import (
	"context"
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type planProvider struct{}

func (planProvider) Describe(d, b yaml.Node, s Subject) (Description, error) {
	m, _ := YAMLMap(d)
	id, _ := json.Marshal(map[string]string{"server": m["url"].Value, "name": s.Name, "version": s.Version})
	return Description{Type: "test", Identity: id}, nil
}
func (planProvider) Build(Description, func(string) (string, bool)) (Target, error) { panic("offline") }

type unusedTarget struct{}

func (unusedTarget) Submit(context.Context, []Payload) (Submission, error) { panic("offline") }
func TestBatchPlanSnapshotsAndFilters(t *testing.T) {
	ip, op := verifiedFixture(t)
	var n yaml.Node
	yaml.Unmarshal([]byte("targets:\n  z: {type: test, url: second}\n  a: {type: test, url: first, overrides: {absent: {}}}\n"), &n)
	c, e := ParseConfig(*n.Content[0], filepath.Dir(ip), "manifest-digest")
	if e != nil {
		t.Fatal(e)
	}
	counts := map[string]int{}
	p, e := planBatch(c, ip, PlanOptions{}, map[string]Provider{"test": planProvider{}}, func(path string, limit int64) ([]byte, error) { counts[path]++; return ReadBounded(path, limit) })
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Jobs) != 2 || p.Jobs[0].Target != "a" || p.Jobs[1].Target != "z" || len(p.UnusedRules) != 1 || counts[ip] != 1 || counts[op] != 1 {
		t.Fatal(p, counts)
	}
	before, _ := io.ReadAll(p.Jobs[0].Verified.Payloads()[0].Open())
	os.WriteFile(op, []byte("changed"), 0600)
	after, _ := io.ReadAll(p.Jobs[1].Verified.Payloads()[0].Open())
	if string(before) != string(after) {
		t.Fatal("mutable bytes")
	}
	if _, e := os.Stat(filepath.Dir(p.Jobs[0].Record)); !os.IsNotExist(e) {
		t.Fatal("plan wrote directories")
	}
	for _, o := range []PlanOptions{{Artifacts: []string{"absent"}}, {Targets: []string{"z", "z"}}, {Targets: []string{"absent"}}} {
		if _, e := PlanBatch(c, ip, o, map[string]Provider{"test": planProvider{}}); e == nil {
			t.Fatal("invalid filter accepted")
		}
	}
	d := p.Jobs[0].Description
	s := p.Jobs[0].Verified.Source()
	key := PairKey(s, d)
	d.DestinationName = "renamed"
	d.CredentialRefs = []string{"ROTATED"}
	if PairKey(s, d) != key {
		t.Fatal("alias/credential rotation changed slot")
	}
	s.OutputSHA256 = Digest([]byte("other"))
	if PairKey(s, d) == key {
		t.Fatal("changed bytes reuse key")
	}
}

func TestBatchPlanPairAndSnapshotBudgets(t *testing.T) {
	ip, op := verifiedFixture(t)
	raw, _ := os.ReadFile(ip)
	idx, e := ParseIndex(raw)
	if e != nil {
		t.Fatal(e)
	}
	c := Config{Targets: map[string]TargetConfig{}}
	for i := 0; i < PairLimit+1; i++ {
		var n yaml.Node
		n.Encode(map[string]any{"url": fmt.Sprint(i)})
		c.Targets[fmt.Sprint(i)] = TargetConfig{Type: "test", Options: n}
	}
	reads := 0
	_, e = planBatch(c, ip, PlanOptions{}, map[string]Provider{"test": planProvider{}}, func(path string, limit int64) ([]byte, error) { reads++; return ReadBounded(path, limit) })
	if e == nil || e.(*Error).Code != "pair_limit" || reads != 1 {
		t.Fatal(e, reads)
	}
	c.Targets = map[string]TargetConfig{"only": c.Targets["0"]}
	a := idx.Artifacts[0]
	a.ID = "second"
	idx.Artifacts = append(idx.Artifacts, a)
	b, _ := os.ReadFile(op)
	reads = 0
	p, e := planResolved(BatchPlan{IndexSHA256: Digest(raw)}, c, ip, idx, PlanOptions{}, map[string]Provider{"test": planProvider{}}, func(path string, limit int64) ([]byte, error) { reads++; return ReadBounded(path, limit) }, int64(len(b)+1))
	if e == nil || e.(*Error).Code != "snapshot_limit" || reads != 2 || len(p.Jobs) != 2 {
		t.Fatal(e, reads, len(p.Jobs))
	}
}

func TestPairKeyIncludesEachImmutableIdentityField(t *testing.T) {
	ip, _ := verifiedFixture(t)
	v, e := Verify(ip, "application", false)
	if e != nil {
		t.Fatal(e)
	}
	source := v.Source()
	d := Description{Type: "test", DestinationName: "alias", Identity: json.RawMessage(`{"receiver":"one","project":"app"}`), Options: json.RawMessage(`{"caFile":"old.pem"}`), CredentialRefs: []string{"OLD_KEY"}}
	key := PairKey(source, d)
	for _, field := range []string{"index", "artifact", "output", "adapter", "target"} {
		t.Run(field, func(t *testing.T) {
			s, next := source, d
			switch field {
			case "index":
				s.IndexSHA256 = Digest([]byte("other index"))
			case "artifact":
				s.ArtifactID = "other-artifact"
			case "output":
				s.OutputSHA256 = Digest([]byte("other output"))
			case "adapter":
				next.Type = "other-adapter"
			case "target":
				next.Identity = json.RawMessage(`{"receiver":"two","project":"app"}`)
			}
			if PairKey(s, next) == key {
				t.Fatal("immutable field absent from key", field)
			}
		})
	}
	d.DestinationName = "renamed"
	d.Options = json.RawMessage(`{"caFile":"rotated.pem","apiKeyEnv":"NEW_KEY"}`)
	d.CredentialRefs = []string{"NEW_KEY"}
	if PairKey(source, d) != key {
		t.Fatal("transport reference rotation changed identity key")
	}
}
