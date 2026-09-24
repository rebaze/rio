package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/delivery/runner"
)

func recordFixture(t *testing.T) (string, string, string) {
	t.Helper()
	ip, cfg := deliveryFixture(t, "https://unreachable.invalid")
	c, plan, e := batchPreflight(cfg, deliveryOptions{index: ip})
	if e != nil {
		t.Fatal(e)
	}
	job := plan.Jobs[0]
	i, e := runner.PrepareIntent(runner.Prepared{Verified: job.Verified, Description: job.Description, Intent: record.Intent{RioVersion: "test", Binding: "app", ConfigSHA256: c.SHA256}})
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(t.TempDir(), "first,comma")
	w, e := record.Create(p, i)
	if e != nil {
		t.Fatal(e)
	}
	w.Close()
	prior, _ := record.Read(p)
	i.Retry = &record.Retry{AttemptID: prior.Events[0].AttemptID, SHA256: prior.SHA256, PathHint: "/never/follow"}
	var o map[string]any
	json.Unmarshal(i.Destination.Options, &o)
	o["apiKeyEnv"] = "ROTATED_KEY"
	o["caFile"] = "/missing/rotated-ca.pem"
	i.Destination.Options, _ = json.Marshal(o)
	i.Destination.CredentialRefs = []string{"ROTATED_KEY"}
	q := filepath.Join(t.TempDir(), "second")
	w, e = record.Create(q, i)
	if e != nil {
		t.Fatal(e)
	}
	w.Close()
	os.Remove(cfg)
	os.Remove(filepath.Join(filepath.Dir(ip), "bom.json"))
	return ip, p, q
}
func recordRun(t *testing.T, args ...string) (int, map[string]any, string) {
	t.Helper()
	var out, err bytes.Buffer
	code := Main(append(args, "--json"), &out, &err)
	var m map[string]any
	dec := json.NewDecoder(&out)
	dec.UseNumber()
	if e := dec.Decode(&m); e != nil {
		t.Fatalf("missing JSON code=%d stdout=%q stderr=%q", code, out.String(), err.String())
	}
	var extra any
	if e := dec.Decode(&extra); e != io.EOF {
		t.Fatal("extra stdout")
	}
	return code, m, err.String()
}
func TestRecordOfflineRotatedRetryAndInspect(t *testing.T) {
	ip, p, q := recordFixture(t)
	builds, env := 0, 0
	oldBuild, oldEnv := deliveryBuild, deliveryLookupEnv
	deliveryBuild = func(delivery.Provider, delivery.Description) (delivery.Target, error) {
		builds++
		return nil, delivery.Fail("unexpected", "build")
	}
	deliveryLookupEnv = func(string) (string, bool) { env++; return "must-never-be-read", true }
	defer func() { deliveryBuild = oldBuild; deliveryLookupEnv = oldEnv }()
	t.Setenv("ROTATED_KEY", "synthetic-secret-invalid\n")
	out := filepath.Join(t.TempDir(), "record.json")
	code, r, err := recordRun(t, "record", "--index", ip, "--delivery-record", q, "--delivery-record", p, "--output", out, "--quiet")
	if code != 0 || r["operation"] != "record" || r["outcome"] != "written" || r["outputMayExist"] != true || r["output"] == nil || err != "" {
		t.Fatal(code, r, err)
	}
	os.RemoveAll(filepath.Dir(ip))
	os.RemoveAll(p)
	os.RemoveAll(q)
	code, r, err = recordRun(t, "record", "inspect", "--file", out, "--quiet")
	if code != 0 || r["operation"] != "record-inspect" || r["outcome"] != "valid" || r["record"] == nil || r["outputMayExist"] != false || err != "" {
		t.Fatal(code, r, err)
	}
	if builds != 0 || env != 0 {
		t.Fatal("offline operation constructed client or resolved credentials")
	}
	b, _ := os.ReadFile(out)
	if bytes.Contains(b, []byte("synthetic-secret")) {
		t.Fatal("secret leaked")
	}
}
func TestRecordFlagsAndRefusals(t *testing.T) {
	ip, _, _ := recordFixture(t)
	for _, extra := range [][]string{{"--manifest", "missing"}, {"--out", "ignored"}} {
		out := filepath.Join(t.TempDir(), "r.json")
		code, r, _ := recordRun(t, append([]string{"record", "--index", ip, "--output", out}, extra...)...)
		if code != 2 || r["outcome"] != "error" || r["error"] == nil || r["outputMayExist"] != false {
			t.Fatal(code, r)
		}
		code, r, _ = recordRun(t, append([]string{"record", "inspect", "--file", "missing"}, extra...)...)
		if code != 2 || r["error"] == nil {
			t.Fatal(code, r)
		}
	}
	for _, args := range [][]string{{"record", "extra"}, {"record", "inspect", "extra"}, {"record", "--allow-failed-gate"}} {
		var o, e bytes.Buffer
		if Main(args, &o, &e) != 2 || o.Len() != 0 {
			t.Fatal("syntax accepted", args)
		}
	}
	code, r, _ := recordRun(t, "record", "inspect")
	if code != 2 || r["error"] == nil {
		t.Fatal(code, r)
	}
	out := filepath.Join(t.TempDir(), "r.json")
	os.WriteFile(out, []byte("original"), 0600)
	code, r, _ = recordRun(t, "record", "--index", ip, "--output", out)
	if code != 2 || r["outputMayExist"] != false {
		t.Fatal(code, r)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "original" {
		t.Fatal("overwrote output")
	}
}
func TestRecordHumanAndZeroSelection(t *testing.T) {
	ip, _, _ := recordFixture(t)
	b, _ := os.ReadFile(ip)
	b = bytes.Replace(b, []byte(`"gate": "ok"`), []byte(`"gate": "fail"`), 1)
	os.WriteFile(ip, b, 0600)
	out := filepath.Join(t.TempDir(), "r.json")
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"record", "--index", ip, "--output", out}, &stdout, &stderr); code != 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "gate=fail") || !strings.Contains(stderr.String(), "No delivery evidence selected") {
		t.Fatal(code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"record", "inspect", "--file", out, "--quiet"}, &stdout, &stderr); code != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatal(code, stdout.String(), stderr.String())
	}
}
func TestRecordRejectsRetryPolicyDrift(t *testing.T) {
	for _, kind := range []string{"selector", "creation", "transport", "gate"} {
		t.Run(kind, func(t *testing.T) {
			ip, p, q := recordFixture(t)
			file := filepath.Join(q, "00000000000000000000.json")
			raw, _ := os.ReadFile(file)
			var ev record.Event
			json.Unmarshal(raw, &ev)
			var i record.Intent
			json.Unmarshal(ev.Data, &i)
			var options map[string]any
			json.Unmarshal(i.Destination.Options, &options)
			switch kind {
			case "selector":
				options["project"] = map[string]any{"fromSubject": true}
			case "creation":
				options["autoCreate"] = true
			case "transport":
				options["allowHTTP"] = false
			case "gate":
				i.Source.AllowFailedGate = true
			}
			i.Destination.Options, _ = json.Marshal(options)
			ev.Data, _ = json.Marshal(i)
			raw, _ = json.Marshal(ev)
			os.WriteFile(file, raw, 0600)
			out := filepath.Join(t.TempDir(), "r.json")
			code, r, _ := recordRun(t, "record", "--index", ip, "--delivery-record", p, "--delivery-record", q, "--output", out)
			if code != 2 || r["error"] == nil {
				t.Fatal("policy drift accepted", kind, code, r)
			}
		})
	}
}

func TestRecordPreservesProducerContextAndEnrichmentChanges(t *testing.T) {
	for _, example := range []string{"demo-context", "demo-enrichment"} {
		t.Run(example, func(t *testing.T) {
			manifest, e := filepath.Abs(filepath.Join("..", "..", "tools", example, "rio.yaml"))
			if e != nil {
				t.Fatal(e)
			}
			dir := t.TempDir()
			var stdout, stderr bytes.Buffer
			code := Main([]string{"normalize", "--manifest", manifest, "--out", dir, "--gate", "warn", "--attest"}, &stdout, &stderr)
			if code != 0 {
				t.Fatal("normalization fixture", code, stderr.String())
			}
			ip := filepath.Join(dir, "index.json")
			raw, _ := os.ReadFile(ip)
			if !bytes.Contains(raw, []byte(`"before": null`)) {
				t.Fatal("fixture lacks nullable producer changes")
			}
			out := filepath.Join(t.TempDir(), "record.json")
			code, r, err := recordRun(t, "record", "--index", ip, "--output", out)
			if code != 0 {
				t.Fatal("valid producer context cannot be collected", code, r, err)
			}
			code, r, err = recordRun(t, "record", "inspect", "--file", out)
			if code != 0 {
				t.Fatal("valid producer context cannot be inspected", code, r, err)
			}
		})
	}
}

func TestRecordFailedGateAndReceiverOutcomesRemainSuccessfulEvidence(t *testing.T) {
	for _, disposition := range []string{"accepted", "rejected", "unknown"} {
		t.Run(disposition, func(t *testing.T) {
			ip, p, _ := recordFixture(t)
			raw, _ := os.ReadFile(ip)
			raw = bytes.Replace(raw, []byte(`"gate": "ok"`), []byte(`"gate": "fail"`), 1)
			os.WriteFile(ip, raw, 0600)
			file := filepath.Join(p, "00000000000000000000.json")
			b, _ := os.ReadFile(file)
			var ev record.Event
			json.Unmarshal(b, &ev)
			var i record.Intent
			json.Unmarshal(ev.Data, &i)
			i.Source.IndexSHA256 = delivery.Digest(raw)
			i.Source.Gate = "fail"
			i.Source.AllowFailedGate = true
			ev.Data, _ = json.Marshal(i)
			b, _ = json.Marshal(ev)
			os.WriteFile(file, b, 0600)
			sub := delivery.Submission{Disposition: disposition, References: []delivery.Reference{}, Observations: []delivery.Observation{}}
			o := delivery.Observation{Kind: "acknowledgment", Value: disposition, Origin: "receiver", Code: "accepted", HTTPStatus: 200, References: []delivery.Reference{}}
			switch disposition {
			case "accepted":
				sub.References = []delivery.Reference{{Kind: "dependency-track:event-token", Value: "f90934f5-cb88-47ce-81cb-db06fc67d4b4"}}
				o.References = sub.References
			case "rejected":
				o.Code = "upload_rejected"
				o.HTTPStatus = 403
			case "unknown":
				o.Kind = "unavailable"
				o.Value = "unavailable"
				o.Origin = "local"
				o.Code = "transport_unavailable"
				o.HTTPStatus = 0
			}
			sub.Observations = append(sub.Observations, o)
			w, e := record.Open(p)
			if e != nil {
				t.Fatal(e)
			}
			b, _ = json.Marshal(sub)
			if e = w.Append("submission", b); e != nil {
				t.Fatal(e)
			}
			w.Close()
			out := filepath.Join(t.TempDir(), "record.json")
			code, r, err := recordRun(t, "record", "--index", ip, "--delivery-record", p, "--output", out)
			if code != 0 {
				t.Fatal("recorded outcome became collector failure", disposition, code, r, err)
			}
			code, r, err = recordRun(t, "record", "inspect", "--file", out)
			if code != 0 {
				t.Fatal("recorded outcome became inspect failure", code, r, err)
			}
		})
	}
}
func TestRecordRejectsContradictoryAdapterSubmission(t *testing.T) {
	ip, p, _ := recordFixture(t)
	w, e := record.Open(p)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(delivery.Submission{Disposition: "accepted", References: []delivery.Reference{}, Observations: []delivery.Observation{{Kind: "acknowledgment", Value: "accepted", Origin: "receiver", Code: "accepted", HTTPStatus: 200, References: []delivery.Reference{}}}})
	if e = w.Append("submission", b); e != nil {
		t.Fatal("generic journal should permit adapter-owned evidence", e)
	}
	w.Close()
	out := filepath.Join(t.TempDir(), "record.json")
	code, r, _ := recordRun(t, "record", "--index", ip, "--delivery-record", p, "--output", out)
	if code != 2 || r["error"] == nil {
		t.Fatal("unsupported acceptance evidence exported", code, r)
	}
}

func TestRecordPortableSavedCAReferencesRemainOffline(t *testing.T) {
	oldBuild, oldEnv := deliveryBuild, deliveryLookupEnv
	builds, lookups := 0, 0
	deliveryBuild = func(delivery.Provider, delivery.Description) (delivery.Target, error) {
		builds++
		return nil, delivery.Fail("unexpected", "build")
	}
	deliveryLookupEnv = func(string) (string, bool) { lookups++; return "must-not-be-read", true }
	defer func() { deliveryBuild = oldBuild; deliveryLookupEnv = oldEnv }()
	for _, ca := range []string{`/missing/rotated-ca.pem`, `C:\missing\ca.pem`, `C:/missing/../ca.pem`, `\\server\share\ca.pem`} {
		t.Run(ca, func(t *testing.T) {
			ip, p, _ := recordFixture(t)
			file := filepath.Join(p, "00000000000000000000.json")
			raw, _ := os.ReadFile(file)
			var ev record.Event
			json.Unmarshal(raw, &ev)
			var i record.Intent
			json.Unmarshal(ev.Data, &i)
			var options map[string]any
			json.Unmarshal(i.Destination.Options, &options)
			options["caFile"] = ca
			i.Destination.Options, _ = json.Marshal(options)
			ev.Data, _ = json.Marshal(i)
			raw, _ = json.Marshal(ev)
			os.WriteFile(file, raw, 0600)
			out := filepath.Join(t.TempDir(), "record.json")
			code, r, stderr := recordRun(t, "record", "--index", ip, "--delivery-record", p, "--output", out)
			if code != 0 {
				t.Fatal("foreign saved CA reference refused", ca, code, r, stderr)
			}
			code, r, stderr = recordRun(t, "record", "inspect", "--file", out)
			if code != 0 {
				t.Fatal("foreign saved CA reference cannot inspect", code, r, stderr)
			}
		})
	}
	if builds != 0 || lookups != 0 {
		t.Fatal("offline path reference resolved client or credential")
	}
}
