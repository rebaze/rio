package cli

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/index"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func batchFixture(t *testing.T, server string) string {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "target", "rio"), 0700)
	idx := index.New("test", index.FileRef{Path: "rio.yaml", SHA256: delivery.Digest([]byte("old normalization manifest"))})
	for _, id := range []string{"app", "worker", "service"} {
		b := []byte(fmt.Sprintf(`{"bomFormat":"CycloneDX","metadata":{"component":{"name":%q,"version":"1"}}}`, id))
		os.WriteFile(filepath.Join(dir, "target", "rio", id+".json"), b, 0600)
		h := delivery.Digest(b)
		idx.Artifacts = append(idx.Artifacts, index.Artifact{ID: id, Input: index.FileRef{Path: id + ".json", SHA256: h}, Output: index.FileRef{Path: id + ".json", SHA256: h}, SpecVersion: index.SpecVersions{Input: "1.6", Output: "1.6"}, Gate: index.GateOK})
	}
	index.Write(filepath.Join(dir, "target", "rio"), idx)
	os.WriteFile(filepath.Join(dir, "rio.yaml"), []byte(fmt.Sprintf("version: 1\nartifactSets: [{modules: 'missing/*/pom.xml', sbom: missing.json, idFrom: module-directory}]\ndelivery:\n  targets:\n    security:\n      type: dependency-track\n      url: '%s'\n      allowHTTP: true\n", server)), 0600)
	return dir
}
func runBatch(t *testing.T, args ...string) (int, map[string]any, string) {
	t.Helper()
	var out, stderr bytes.Buffer
	code := Main(append(args, "--json"), &out, &stderr)
	var r map[string]any
	dec := json.NewDecoder(&out)
	if e := dec.Decode(&r); e != nil {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, out.String(), stderr.String())
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		t.Fatal("extra JSON")
	}
	if r["schemaVersion"] != float64(2) || r["items"] == nil {
		t.Fatal(r)
	}
	return code, r, stderr.String()
}
func TestDeliveryBatchDefaultsAndPartial(t *testing.T) {
	for _, failAt := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			calls := 0
			names := []string{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "POST" {
					t.Error("lookup requested")
				}
				r.ParseMultipartForm(1 << 20)
				names = append(names, r.FormValue("projectName"))
				w.Header().Set("Content-Type", "application/json")
				if calls == failAt {
					io.WriteString(w, `{}`)
				} else {
					io.WriteString(w, `{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}`)
				}
			}))
			defer srv.Close()
			dir := batchFixture(t, srv.URL)
			t.Chdir(dir)
			t.Setenv("DTRACK_API_KEY", "synthetic-key")
			code, plan, _ := runBatch(t, "delivery", "plan")
			if code != 0 || len(plan["items"].([]any)) != 3 {
				t.Fatal(code, plan)
			}
			if _, e := os.Stat("target/rio/deliveries"); !os.IsNotExist(e) {
				t.Fatal("plan writes")
			}
			code, r, _ := runBatch(t, "deliver")
			items := r["items"].([]any)
			expected := 3
			if failAt > 0 {
				expected = failAt
				if code != 4 {
					t.Fatal(code, r)
				}
			} else if code != 0 {
				t.Fatal(code, r)
			}
			if calls != expected || names[0] != "app" {
				t.Fatal(calls, names)
			}
			if failAt == 2 && r["outcome"] != "partial" {
				t.Fatal(r)
			}
			for i, item := range items {
				state := item.(map[string]any)["state"]
				if i >= expected && state != "unattempted" {
					t.Fatal(items)
				}
			}
			code, _, _ = runBatch(t, "deliver")
			if code != 2 || calls != expected {
				t.Fatal("rerun duplicated", code, calls)
			}
		})
	}
}

func TestDeliveryBatchPreflightRefusesBeforeRequests(t *testing.T) {
	for _, kind := range []string{"credential", "ca", "digest", "existing", "busy", "collision", "alias", "mixed", "empty", "no-targets", "unknown-filter", "duplicate-filter", "record-multiple", "retry-default"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}`)
			}))
			defer srv.Close()
			dir := batchFixture(t, srv.URL)
			t.Chdir(dir)
			t.Setenv("DTRACK_API_KEY", "synthetic-key")
			b, _ := os.ReadFile("rio.yaml")
			args := []string{"deliver"}
			switch kind {
			case "credential":
				b = append(b, []byte(fmt.Sprintf("    z:\n      type: dependency-track\n      url: '%s/other'\n      allowHTTP: true\n      apiKeyEnv: MISSING_BATCH_KEY\n", srv.URL))...)
				t.Setenv("MISSING_BATCH_KEY", "")
			case "ca":
				b = append(b, []byte("      caFile: missing.pem\n")...)
			case "digest":
				os.WriteFile("target/rio/service.json", []byte("tampered"), 0600)
			case "existing", "busy":
				_, p, _ := runBatch(t, "delivery", "plan")
				path := p["items"].([]any)[2].(map[string]any)["record"].(string)
				os.Mkdir(filepath.Dir(path), 0700)
				if kind == "busy" {
					path += ".lock"
				}
				os.Mkdir(path, 0700)
			case "collision":
				b = append(b, []byte("      project: {name: common, version: '1'}\n")...)
			case "alias":
				b = append(b, []byte(fmt.Sprintf("    z: {type: dependency-track, url: '%s', allowHTTP: true}\n", srv.URL))...)
			case "mixed":
				b = append(b, []byte("      overrides:\n        service:\n          project: {uuid: f90934f5-cb88-47ce-81cb-db06fc67d4b4}\n")...)
			case "empty":
				b = append(b, []byte("      exclude: [app, worker, service]\n")...)
			case "no-targets":
				b = []byte("version: 1\nartifacts: [{id: unused, sbom: missing.json}]\n")
			case "unknown-filter":
				args = append(args, "--artifact", "absent")
			case "duplicate-filter":
				args = append(args, "--target", "security", "--target", "security")
			case "record-multiple":
				args = append(args, "--record", "journal")
			case "retry-default":
				args = append(args, "--artifact", "app", "--retry-of", "prior")
			}
			os.WriteFile("rio.yaml", b, 0600)
			code, r, _ := runBatch(t, args...)
			if code != 2 || calls != 0 || r["requestMayHaveOccurred"] != false {
				t.Fatal(kind, code, r, calls)
			}
			entries, _ := os.ReadDir("target/rio/deliveries")
			for _, ent := range entries {
				if strings.HasSuffix(ent.Name(), ".lock") && kind != "busy" {
					t.Fatal("owned lock leaked")
				}
			}
		})
	}
}

func TestDeliveryBatchOverridesExclusionsAndUnused(t *testing.T) {
	dir := batchFixture(t, "https://EXAMPLE.test:443")
	t.Chdir(dir)
	b, _ := os.ReadFile("rio.yaml")
	b = append(b, []byte("      exclude: [worker, absent]\n      overrides:\n        app: {project: {name: explicit, version: '2'}}\n        absent: {project: {fromSubject: true}}\n    unavailable:\n      type: dependency-track\n      url: https://unavailable.invalid\n      apiKeyEnv: UNSET_UNUSED_KEY\n      caFile: missing.pem\n")...)
	os.WriteFile("rio.yaml", b, 0600)
	code, r, _ := runBatch(t, "delivery", "plan", "--target", "security")
	if code != 0 || len(r["items"].([]any)) != 2 || len(r["unusedRules"].([]any)) != 2 {
		t.Fatal(code, r)
	}
	items := r["items"].([]any)
	id := items[0].(map[string]any)["destination"].(map[string]any)["identity"].(map[string]any)
	if id["url"] != "https://example.test" || id["project"].(map[string]any)["name"] != "explicit" {
		t.Fatal(id)
	}
}

func TestDeliveryBatchPersistenceKeepsObservedAcceptance(t *testing.T) {
	calls := 0
	second := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		io.Copy(io.Discard, r.Body)
		if calls == 2 {
			os.Mkdir(filepath.Join(second, "unexpected"), 0700)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}`)
	}))
	defer srv.Close()
	dir := batchFixture(t, srv.URL)
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "synthetic-key")
	_, plan, _ := runBatch(t, "delivery", "plan")
	second = plan["items"].([]any)[1].(map[string]any)["record"].(string)
	code, r, _ := runBatch(t, "deliver")
	items := r["items"].([]any)
	if code != 3 || r["outcome"] != "partial" || calls != 2 || items[1].(map[string]any)["state"] != "accepted" || items[2].(map[string]any)["state"] != "unattempted" {
		t.Fatal(code, r, calls)
	}
	if items[1].(map[string]any)["result"].(map[string]any)["persisted"] != false {
		t.Fatal(r)
	}
}

func TestOfflineUnifiedManifestExplicitAndSets(t *testing.T) {
	oldBuild, oldLookup := deliveryBuild, deliveryLookupEnv
	defer func() { deliveryBuild = oldBuild; deliveryLookupEnv = oldLookup }()
	deliveryBuild = func(delivery.Provider, delivery.Description) (delivery.Target, error) {
		t.Fatal("offline client constructed")
		return nil, nil
	}
	deliveryLookupEnv = func(string) (string, bool) { t.Fatal("offline credential resolved"); return "", false }
	bom, e := os.ReadFile("../../tools/demo-delivery/bom.json")
	if e != nil {
		t.Fatal(e)
	}
	for _, sets := range []bool{false, true} {
		t.Run(fmt.Sprint(sets), func(t *testing.T) {
			dir := t.TempDir()
			os.MkdirAll(filepath.Join(dir, "services", "server"), 0700)
			os.WriteFile(filepath.Join(dir, "services", "server", "pom.xml"), []byte("<project/>"), 0600)
			os.WriteFile(filepath.Join(dir, "services", "server", "bom.json"), bom, 0600)
			intake := "artifacts: [{id: app, sbom: services/server/bom.json}]"
			if sets {
				intake = "artifactSets: [{modules: 'services/*/pom.xml', sbom: bom.json, idFrom: module-directory}]"
			}
			cfg := filepath.Join(dir, "rio.yaml")
			os.WriteFile(cfg, []byte("version: 1\n"+intake+"\ndelivery: {targets: {security: {type: dependency-track, url: https://unreachable.invalid, caFile: missing.pem, apiKeyEnv: UNSET_KEY}}}\n"), 0600)
			for _, op := range []string{"normalize", "plan"} {
				var out, stderr bytes.Buffer
				if code := Main([]string{op, "--manifest", cfg, "--out", filepath.Join(dir, "out")}, &out, &stderr); code != 0 {
					t.Fatal(op, code, stderr.String())
				}
			}
		})
	}
}

func TestReconcileRefusesTransportPolicyDrift(t *testing.T) {
	ip, cfg := deliveryFixture(t, "https://example.test")
	_, _, a, _, e := singlePreflight(cfg, ip, false)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(cfg)
	b = bytes.Replace(b, []byte("allowHTTP: true"), []byte("allowHTTP: false"), 1)
	os.WriteFile(cfg, b, 0600)
	_, _, d, _, e := singlePreflight(cfg, ip, false)
	if e != nil {
		t.Fatal(e)
	}
	if samePolicy(a, d, true) || samePolicy(a, d, false) {
		t.Fatal("transport policy drift accepted")
	}
}

func TestLegacyJournalReconcilesByRecordedTargetAfterInputsDisappear(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" {
			t.Error("reconcile resubmitted")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"processing":false}`)
	}))
	defer srv.Close()
	ip, cfg := deliveryFixture(t, srv.URL)
	_, v, d, _, e := singlePreflight(cfg, ip, false)
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Dir(cfg)
	p := filepath.Join(dir, "legacy")
	w, e := record.Create(p, record.Intent{RioVersion: "before-85", Binding: "removed-old-binding", ConfigSHA256: delivery.Digest([]byte("old separate snapshot")), Source: v.Source(), Destination: d, Payloads: []delivery.PayloadRef{v.Payloads()[0].Ref()}})
	if e != nil {
		t.Fatal(e)
	}
	refs := []delivery.Reference{{Kind: "dependency-track:event-token", Value: "f90934f5-cb88-47ce-81cb-db06fc67d4b4"}}
	sub, _ := json.Marshal(delivery.Submission{Disposition: "accepted", References: refs, Observations: []delivery.Observation{{Kind: "acknowledgment", Value: "accepted", Origin: "receiver", Code: "accepted", HTTPStatus: 200, References: refs}}})
	if e = w.Append("submission", sub); e != nil {
		t.Fatal(e)
	}
	w.Close()
	before, _ := record.Read(p)
	os.Remove(ip)
	os.Remove(filepath.Join(dir, "bom.json"))
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	os.WriteFile(filepath.Join(dir, "rotated.pem"), ca, 0600)
	b, _ := os.ReadFile(cfg)
	b = append(b, []byte("      apiKeyEnv: ROTATED_LEGACY_KEY\n      caFile: rotated.pem\n")...)
	os.WriteFile(cfg, b, 0600)
	t.Setenv("ROTATED_LEGACY_KEY", "synthetic-key")
	code, r, _ := deliveryRun(t, "delivery", "reconcile", "--record", p, "--manifest", cfg)
	if code != 0 || calls != 1 || r["activity"] != "not-observed" {
		t.Fatal(code, r, calls)
	}
	after, _ := record.Read(p)
	if after.Intent.Binding != "removed-old-binding" || after.Intent.ConfigSHA256 != before.Intent.ConfigSHA256 || after.Intent.Source.IndexSHA256 != before.Intent.Source.IndexSHA256 {
		t.Fatal("historical snapshot rewritten")
	}
	var observation record.Reconciliation
	if e := json.Unmarshal(after.Events[len(after.Events)-1].Data, &observation); e != nil || observation.ConfigSHA256 != delivery.Digest(b) {
		t.Fatal(e, observation)
	}
	os.Remove(cfg)
	code, _, _ = deliveryRun(t, "delivery", "inspect", "--record", p)
	if code != 0 {
		t.Fatal("inspection required manifest")
	}
}

func TestDeliveryDeclarationLimitHasSafeCode(t *testing.T) {
	dir := batchFixture(t, "https://example.test")
	t.Chdir(dir)
	b, _ := os.ReadFile("rio.yaml")
	b = append(b, []byte("      caFile: '"+strings.Repeat("secret-canary", 100000)+"'\n")...)
	os.WriteFile("rio.yaml", b, 0600)
	code, r, stderr := runBatch(t, "delivery", "plan")
	if code != 2 || r["error"].(map[string]any)["code"] != "size_limit" || strings.Contains(stderr, "secret-canary") {
		t.Fatal(code, r, stderr)
	}
}

func TestDeliveryBatchSendsOriginalSnapshotsAfterSourceReplacement(t *testing.T) {
	calls := 0
	hashes := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if e := r.ParseMultipartForm(1 << 20); e != nil {
			t.Error(e)
		}
		f, _, e := r.FormFile("bom")
		if e != nil {
			t.Error(e)
			return
		}
		b, _ := io.ReadAll(f)
		f.Close()
		hashes[delivery.Digest(b)]++
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}`)
	}))
	defer srv.Close()
	dir := batchFixture(t, srv.URL)
	t.Chdir(dir)
	t.Setenv("DTRACK_API_KEY", "synthetic-key")
	original, _ := os.ReadFile("target/rio/app.json")
	b, _ := os.ReadFile("rio.yaml")
	b = append(b, []byte(fmt.Sprintf("    mirror: {type: dependency-track, url: '%s/mirror', allowHTTP: true}\n", srv.URL))...)
	os.WriteFile("rio.yaml", b, 0600)
	old := deliveryBuild
	defer func() { deliveryBuild = old }()
	builds := 0
	deliveryBuild = func(p delivery.Provider, d delivery.Description) (delivery.Target, error) {
		builds++
		if builds == 1 {
			os.WriteFile("target/rio/app.json", []byte("replaced after complete planning"), 0600)
		}
		return old(p, d)
	}
	code, r, _ := runBatch(t, "deliver")
	if code != 0 || calls != 6 || hashes[delivery.Digest(original)] != 2 {
		t.Fatal(code, r, calls, hashes)
	}
}

func TestDeliveryBatchCanonicalAliasesCollide(t *testing.T) {
	dir := batchFixture(t, "https://EXAMPLE.test:443")
	t.Chdir(dir)
	b, _ := os.ReadFile("rio.yaml")
	b = append(b, []byte("    alias: {type: dependency-track, url: https://example.test}\n")...)
	os.WriteFile("rio.yaml", b, 0600)
	code, r, _ := runBatch(t, "delivery", "plan")
	if code != 2 || r["error"].(map[string]any)["code"] != "target_collision" {
		t.Fatal(code, r)
	}
}

func TestDeliveryBatchOutputAndRemovedFlags(t *testing.T) {
	dir := batchFixture(t, "https://example.test")
	t.Chdir(dir)
	code, r, stderr := runBatch(t, "delivery", "plan", "--quiet")
	if code != 0 || stderr != "" || r["outcome"] != "ready" {
		t.Fatal(code, r, stderr)
	}
	for _, flag := range []string{"--config", "--delivery"} {
		code, r, stderr := runBatch(t, "deliver", flag, "legacy", "--quiet")
		if code != 2 || r["error"].(map[string]any)["code"] != "removed_flag" || !strings.Contains(stderr, "rio.yaml") || !strings.Contains(stderr, "--target") {
			t.Fatal(code, r, stderr)
		}
	}
	code, _, stderr = deliveryRun(t, "delivery", "inspect", "--record", "missing", "--manifest", "rio.yaml")
	if code != 2 || !strings.Contains(stderr, "irrelevant") {
		t.Fatal(code, stderr)
	}
	var out, human bytes.Buffer
	code = Main([]string{"delivery", "plan"}, &out, &human)
	if code != 0 || out.Len() != 0 {
		t.Fatal(code, out.String(), human.String())
	}
	for _, s := range []string{"artifact=app", "target=security", "project=", "record=", "state=ready"} {
		if !strings.Contains(human.String(), s) {
			t.Fatal("missing human fact", s, human.String())
		}
	}
}

func TestDeliveryBatchRejectedSuffixAndCleanup(t *testing.T) {
	for _, cleanup := range []bool{false, true} {
		t.Run(fmt.Sprint(cleanup), func(t *testing.T) {
			calls := 0
			last := ""
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				io.Copy(io.Discard, r.Body)
				if cleanup {
					os.WriteFile(filepath.Join(last+".lock", "obstruction"), []byte("block cleanup"), 0600)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(403)
				io.WriteString(w, `{"error":"synthetic"}`)
			}))
			defer srv.Close()
			dir := batchFixture(t, srv.URL)
			t.Chdir(dir)
			t.Setenv("DTRACK_API_KEY", "synthetic-key")
			_, p, _ := runBatch(t, "delivery", "plan")
			last = p["items"].([]any)[2].(map[string]any)["record"].(string)
			code, r, _ := runBatch(t, "deliver")
			want := 5
			if cleanup {
				want = 3
			}
			items := r["items"].([]any)
			if code != want || calls != 1 || r["outcome"] != "rejected" || items[0].(map[string]any)["state"] != "rejected" || items[1].(map[string]any)["state"] != "unattempted" || items[2].(map[string]any)["state"] != "unattempted" {
				t.Fatal(code, r, calls)
			}
			if cleanup && r["error"].(map[string]any)["code"] != "persistence_failed" {
				t.Fatal(r)
			}
		})
	}
}
func TestDeliveryBatchEmptyIndexAndInvalidUnusedOptions(t *testing.T) {
	dir := batchFixture(t, "https://example.test")
	t.Chdir(dir)
	b, _ := os.ReadFile("rio.yaml")
	b = append(b, []byte("    unused: {type: dependency-track, url: https://other.test, project: {name: invalid, version: 1}}\n")...)
	os.WriteFile("rio.yaml", b, 0600)
	code, r, _ := runBatch(t, "delivery", "plan", "--target", "security")
	if code != 2 || r["error"].(map[string]any)["code"] != "invalid_config" {
		t.Fatal(code, r)
	}
	b = bytes.Replace(b, []byte("version: 1}}"), []byte("version: '1'}}"), 1)
	os.WriteFile("rio.yaml", b, 0600)
	raw, _ := os.ReadFile("target/rio/index.json")
	idx, e := delivery.ParseIndex(raw)
	if e != nil {
		t.Fatal(e)
	}
	idx.Artifacts = []index.Artifact{}
	index.Write("target/rio", &idx)
	code, r, _ = runBatch(t, "delivery", "plan")
	if code != 2 || r["error"].(map[string]any)["code"] != "no_deliveries_selected" {
		t.Fatal(code, r)
	}
}

func TestDeliveryBatchLateDigestFailureReportsCompleteSelection(t *testing.T) {
	dir := batchFixture(t, "https://example.test")
	t.Chdir(dir)
	os.WriteFile("target/rio/worker.json", []byte("tampered"), 0600)
	code, r, _ := runBatch(t, "deliver")
	items := r["items"].([]any)
	if code != 2 || len(items) != 3 {
		t.Fatal(code, r)
	}
	if items[0].(map[string]any)["state"] != "unattempted" || items[1].(map[string]any)["state"] != "error" || items[2].(map[string]any)["state"] != "unattempted" {
		t.Fatal(items)
	}
}

func TestHumanDeliveryPlanShowsEffectiveCreationPolicy(t *testing.T) {
	for _, tc := range []struct{ name, options, want string }{
		{"default", "", "autoCreate=false"},
		{"enabled", "      autoCreate: true\n", "autoCreate=true"},
		{"uuid", "      project: {uuid: f90934f5-cb88-47ce-81cb-db06fc67d4b4}\n", "autoCreate=not-applicable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := batchFixture(t, "https://example.test")
			t.Chdir(dir)
			b, _ := os.ReadFile("rio.yaml")
			os.WriteFile("rio.yaml", append(b, []byte(tc.options)...), 0600)
			var out, stderr bytes.Buffer
			code := Main([]string{"delivery", "plan", "--artifact", "app"}, &out, &stderr)
			if code != 0 || !strings.Contains(stderr.String(), tc.want) {
				t.Fatal(code, out.String(), stderr.String())
			}
		})
	}
}
