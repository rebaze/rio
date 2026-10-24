package receipt

import (
	"encoding/json"
	"testing"
)

func gateRelationFixture() Document {
	d := fixture()
	d.Run.Stages["normalize"] = "completed"
	d.Run.Stages["checks"] = "passed"
	return d
}

func failReceiptGate(d *Document, mode string) {
	d.Artifacts[0].Checks.Mode = mode
	d.Artifacts[0].Checks.Gate = "fail"
	d.Artifacts[0].Checks.Findings = 1
	d.Run.Stages["checks"] = "failed"
}

func TestGateRelationsRejectContradictoryReceipts(t *testing.T) {
	cases := map[string]func(*Document){
		"successful enforced gate failure": func(d *Document) {
			failReceiptGate(d, "fail")
			d.Deliveries = nil
		},
		"delivery after enforced gate failure despite failed outcome": func(d *Document) {
			failReceiptGate(d, "fail")
			d.Run.Outcome = "failed"
		},
		"failed sibling blocks whole pipeline": func(d *Document) {
			other := d.Artifacts[0]
			other.ID = "blocked-sibling"
			checks := *other.Checks
			checks.Gate, checks.Findings = "fail", 1
			other.Checks = &checks
			d.Artifacts = append(d.Artifacts, other)
			d.Run.Stages["checks"] = "failed"
			d.Run.Outcome = "partial"
		},
		"warn failure called passed": func(d *Document) {
			failReceiptGate(d, "warn")
			d.Run.Stages["checks"] = "passed"
		},
		"effective mode contradicts explicit flag": func(d *Document) {
			failReceiptGate(d, "warn")
			d.Run.Overrides = map[string]string{"gate": "fail"}
		},
		"one invocation cannot mix local gate policies": func(d *Document) {
			other := d.Artifacts[0]
			other.ID = "other"
			checks := *other.Checks
			checks.Mode, checks.Gate, checks.Findings = "warn", "fail", 1
			other.Checks = &checks
			d.Artifacts = append(d.Artifacts, other)
			d.Run.Stages["checks"] = "failed"
		},
		"pipeline borrows pre-existing checks": func(d *Document) {
			d.Artifacts[0].Checks.Mode = "pre-existing"
		},
		"successful failed checks stage without warn failure": func(d *Document) {
			d.Run.Stages["checks"] = "failed"
		},
		"schema failure cannot be overridden by warn": func(d *Document) {
			d.Artifacts[0].Checks.Mode = "warn"
			d.Artifacts[0].Checks.Schema = "fail"
			d.Run.Stages["checks"] = "failed"
		},
		"standalone failed gate without authorization": func(d *Document) {
			makeStandaloneReceipt(d, false)
		},
		"standalone false override is not authorization": func(d *Document) {
			makeStandaloneReceipt(d, false)
			d.Run.Overrides = map[string]string{"allow-failed-gate": "false"}
		},
		"standalone claims current checks": func(d *Document) {
			makeStandaloneReceipt(d, true)
			d.Artifacts[0].Checks.Mode = "warn"
		},
		"historical failed gate cannot be labeled passed": func(d *Document) {
			makeStandaloneReceipt(d, true)
			d.Run.Stages["checks"] = "passed"
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			d := gateRelationFixture()
			change(&d)
			// Marshal with encoding/json so the reader is tested independently of
			// the publisher's validation of the same contradictory assertions.
			raw, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = Parse(raw); err == nil {
				t.Fatal("accepted contradictory gate policy, stage, or delivery facts")
			}
			if _, err = Marshal(d); err == nil {
				t.Fatal("published contradictory gate policy, stage, or delivery facts")
			}
		})
	}
}

func makeStandaloneReceipt(d *Document, authorized bool) {
	d.Run.Operation = "deliver"
	d.Run.Stages["normalize"] = "pre-existing"
	d.Run.Stages["checks"] = "pre-existing"
	d.Artifacts[0].PreExisting = true
	d.Artifacts[0].Checks.Mode = "pre-existing"
	d.Artifacts[0].Checks.Gate = "fail"
	d.Artifacts[0].Checks.Findings = 1
	if authorized {
		d.Run.Overrides = map[string]string{"allow-failed-gate": "true"}
	}
}

func TestGateRelationsPreserveScopedFailuresAndOverrides(t *testing.T) {
	cases := map[string]func(*Document){
		"warn failure can succeed and deliver": func(d *Document) { failReceiptGate(d, "warn") },
		"standalone normalization warn failure can succeed": func(d *Document) {
			failReceiptGate(d, "warn")
			d.Run.Operation = "normalize"
			d.Run.Stages["delivery"] = "not-applicable"
			d.Deliveries = nil
		},
		"enforced failure retained before delivery": func(d *Document) {
			failReceiptGate(d, "fail")
			d.Run.Outcome = "failed"
			d.Run.Stages["delivery"] = "not-attempted"
			d.Deliveries = nil
		},
		"incomplete local work with failed gate": func(d *Document) {
			failReceiptGate(d, "fail")
			d.Run.Outcome, d.Run.FinishedAt = "incomplete", ""
			d.Run.Stages["checks"] = "incomplete"
			d.Deliveries = nil
		},
		"standalone explicitly authorized failed gate": func(d *Document) { makeStandaloneReceipt(d, true) },
		"standalone refused failed gate": func(d *Document) {
			makeStandaloneReceipt(d, false)
			d.Run.Outcome = "failed"
			d.Deliveries = nil
		},
		"reconciliation does not enforce historical gate": func(d *Document) {
			makeStandaloneReceipt(d, false)
			d.Run.Operation = "reconcile"
			v := &d.Deliveries[0]
			v.State = "observed"
			v.Submitted, v.Intended = nil, nil
			v.Responses = []Response{{Kind: "activity", Value: "not-observed", HTTPStatus: 200}}
		},
		"unsupported schema stays unavailable": func(d *Document) {
			d.Artifacts[0].Checks.Schema = "not-available"
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			d := gateRelationFixture()
			change(&d)
			raw, err := Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = Parse(raw); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFailedRequirementsAreScopedOrderedAndCounted(t *testing.T) {
	valid := func(d *Document) {
		failReceiptGate(d, "warn")
		d.Artifacts[0].Checks.SubjectRequirements = []string{"name", "version", "securityContact"}
		d.Artifacts[0].Checks.Failed = []FailedRequirement{{Requirement: "subject.securityContact", Count: 1}, {Requirement: "components.name", Count: 1}}
		// One subject finding plus one failing component.
		d.Artifacts[0].Checks.Findings = 2
	}
	d := gateRelationFixture()
	valid(&d)
	if _, err := Marshal(d); err != nil {
		t.Fatalf("valid failed requirements refused: %v", err)
	}
	cases := map[string]func(*Document){
		"failed requirements on a passing gate": func(d *Document) {
			d.Artifacts[0].Checks.Failed = []FailedRequirement{{Requirement: "subject.name", Count: 1}}
		},
		"unknown requirement": func(d *Document) {
			valid(d)
			d.Artifacts[0].Checks.Failed[0].Requirement = "subject.license"
		},
		"out of order": func(d *Document) {
			valid(d)
			f := d.Artifacts[0].Checks.Failed
			f[0], f[1] = f[1], f[0]
		},
		"duplicate": func(d *Document) {
			valid(d)
			d.Artifacts[0].Checks.Failed[1] = d.Artifacts[0].Checks.Failed[0]
		},
		"zero count": func(d *Document) {
			valid(d)
			d.Artifacts[0].Checks.Failed[1].Count = 0
		},
		"subject counted twice": func(d *Document) {
			valid(d)
			d.Artifacts[0].Checks.Failed[0].Count = 2
		},
		"more components than evaluated": func(d *Document) {
			valid(d)
			d.Artifacts[0].Checks.Failed[1].Count = 2
		},
		"subject requirement that was not required": func(d *Document) {
			valid(d)
			d.Artifacts[0].Checks.SubjectRequirements = []string{"name", "version"}
		},
		"component requirement that was not selected": func(d *Document) {
			valid(d)
			d.Artifacts[0].Checks.Failed[1].Requirement = "components.purl"
		},
		"subject and component failures in one finding": func(d *Document) {
			valid(d)
			d.Artifacts[0].Checks.Findings = 1
		},
		"more findings than the failures explain": func(d *Document) {
			valid(d)
			d.Artifacts[0].Checks.Findings = 3
		},
		"component failures beyond the findings": func(d *Document) {
			valid(d)
			d.Artifacts[0].Checks.Failed = d.Artifacts[0].Checks.Failed[1:]
			d.Artifacts[0].Checks.Findings = 0
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			d := gateRelationFixture()
			change(&d)
			raw, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = Parse(raw); err == nil {
				t.Fatal("accepted inconsistent failed requirements")
			}
		})
	}
}

func TestSubjectDigestFailureOrdersAfterSecurityContact(t *testing.T) {
	build := func(failed ...FailedRequirement) Document {
		d := gateRelationFixture()
		failReceiptGate(&d, "warn")
		d.Artifacts[0].Checks.SubjectRequirements = []string{"name", "version", "securityContact", "digest"}
		d.Artifacts[0].Checks.Failed = failed
		d.Artifacts[0].Checks.Findings = 1
		return d
	}
	ok := build(FailedRequirement{Requirement: "subject.securityContact", Count: 1}, FailedRequirement{Requirement: "subject.digest", Count: 1})
	if _, err := Marshal(ok); err != nil {
		t.Fatalf("valid order refused: %v", err)
	}
	bad := build(FailedRequirement{Requirement: "subject.digest", Count: 1}, FailedRequirement{Requirement: "subject.securityContact", Count: 1})
	if _, err := Marshal(bad); err == nil {
		t.Fatal("digest before securityContact must be refused")
	}
	notRequired := build(FailedRequirement{Requirement: "subject.digest", Count: 1})
	notRequired.Artifacts[0].Checks.SubjectRequirements = []string{"name", "version"}
	if _, err := Marshal(notRequired); err == nil {
		t.Fatal("a digest failure without the requirement must be refused")
	}
}
