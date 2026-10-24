package gate_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/rebaze/rio/internal/gate"
)

const digestHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func digestOnly() gate.Requirements {
	return gate.Requirements{Subject: []gate.Requirement{gate.RequireDigest}}
}

func distRef(hashes string) string {
	return `{"type": "distribution", "url": "https://example.com/app.tgz", "hashes": [` + hashes + `]}`
}

func TestDigestIsOnlyCheckedWhenRequired(t *testing.T) {
	got := gate.Check(load(t, docWith(goodSubject)), nil)
	if !got.OK() {
		t.Fatalf("%+v", got.Findings)
	}
	for _, e := range got.Evaluations {
		if e.Requirement == string(gate.RequireDigest) {
			t.Fatalf("an unrequired digest must not be reported as evaluated: %+v", e)
		}
	}
}

func TestDigestPassesWithSHA256Distribution(t *testing.T) {
	ref := distRef(`{"alg": "SHA-1", "content": "abc"}, {"alg": "SHA-256", "content": "` + digestHex + `"}`)
	got := gate.CheckRequirements(load(t, docWith(subjectWithContact(ref))), digestOnly())
	if !got.OK() {
		t.Fatalf("%+v", got.Findings)
	}
	want := gate.Evaluation{Scope: "subject", Requirement: "digest", Evaluated: 1, Outcome: "pass"}
	if diff := cmp.Diff(want, got.Evaluations[2]); diff != "" {
		t.Fatalf("evaluation (-want +got):\n%s", diff)
	}
}

func TestDigestFails(t *testing.T) {
	cases := map[string]string{
		"no references":   ``,
		"other type":      `{"type": "website", "url": "https://example.com", "hashes": [{"alg": "SHA-256", "content": "` + digestHex + `"}]}`,
		"no hashes":       `{"type": "distribution", "url": "https://example.com/app.tgz"}`,
		"only SHA-512":    distRef(`{"alg": "SHA-512", "content": "` + digestHex + `"}`),
		"short content":   distRef(`{"alg": "SHA-256", "content": "abc123"}`),
		"non hex":         distRef(`{"alg": "SHA-256", "content": "` + digestHex[:63] + `z"}`),
		"missing content": distRef(`{"alg": "SHA-256"}`),
	}
	for name, ref := range cases {
		t.Run(name, func(t *testing.T) {
			got := gate.CheckRequirements(load(t, docWith(subjectWithContact(ref))), digestOnly())
			want := []gate.Finding{{Subject: true, Missing: []string{"digest"}}}
			if diff := cmp.Diff(want, got.Findings); diff != "" {
				t.Fatalf("findings (-want +got):\n%s", diff)
			}
			if e := got.Evaluations[2]; e.Requirement != "digest" || e.Outcome != "fail" || e.Failed != 1 {
				t.Fatalf("evaluation %+v", e)
			}
		})
	}
}

func TestDigestFollowsSecurityContactInFixedOrder(t *testing.T) {
	doc := docWith(`"metadata": {"component": {"type": "application", "version": "1.0.0"}}`)
	got := gate.CheckRequirements(load(t, doc), gate.Requirements{Subject: []gate.Requirement{gate.RequireDigest, gate.RequireSecurityContact}})
	want := []gate.Finding{{Subject: true, Missing: []string{"name", "securityContact", "digest"}}}
	if diff := cmp.Diff(want, got.Findings); diff != "" {
		t.Fatalf("findings (-want +got):\n%s", diff)
	}
	var order []string
	for _, e := range got.Evaluations {
		order = append(order, e.Requirement)
	}
	if diff := cmp.Diff([]string{"name", "version", "securityContact", "digest"}, order); diff != "" {
		t.Fatalf("evaluations (-want +got):\n%s", diff)
	}
}

func TestDigestIsNeverAComponentRequirement(t *testing.T) {
	got := gate.CheckRequirements(load(t, docWith(goodSubject, compGson)), gate.Requirements{Components: []gate.Requirement{gate.RequireDigest}})
	if !got.OK() {
		t.Fatalf("%+v", got.Findings)
	}
}
