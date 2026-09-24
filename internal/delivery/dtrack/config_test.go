package dtrack

import (
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"gopkg.in/yaml.v3"
	"strings"
	"testing"
)

func node(t *testing.T, s string) yaml.Node {
	t.Helper()
	var n yaml.Node
	if e := yaml.Unmarshal([]byte(s), &n); e != nil {
		t.Fatal(e)
	}
	return *n.Content[0]
}
func TestDescribe(t *testing.T) {
	for _, tc := range []struct {
		name, dst, binding string
		ok                 bool
	}{
		{"pair", "url: https://EXAMPLE.test:443/prefix/", "project: {name: '@app', version: '1'}", true},
		{"uuid", "url: https://example.test", "project: {uuid: F90934F5-CB88-47CE-81CB-DB06FC67D4B4}", true},
		{"subject", "url: https://example.test", "project: {fromSubject: true}", true},
		{"offline missing CA", "url: https://example.test\ncaFile: /nonexistent\napiKeyEnv: ABSENT_KEY", "project: {name: app, version: '1'}", true},
		{"numeric version", "url: https://example.test", "project: {name: app, version: 1}", false},
		{"uuid autocreate false", "url: https://example.test", "project: {uuid: f90934f5-cb88-47ce-81cb-db06fc67d4b4}\nautoCreate: false", false},
		{"mixed", "url: https://example.test", "project: {name: app, version: '1', fromSubject: true}", false},
		{"partial", "url: https://example.test", "project: {name: app}", false},
		{"space", "url: https://example.test", "project: {name: ' app', version: '1'}", false},
		{"false", "url: https://example.test", "project: {fromSubject: false}", false},
		{"bad uuid", "url: https://example.test", "project: {uuid: bad}", false},
		{"env", "url: https://example.test\napiKeyEnv: bad-key", "project: {name: app, version: '1'}", false},
		{"userinfo", "url: https://secret:password@example.test", "project: {name: app, version: '1'}", false},
		{"dot", "url: https://example.test/a/../b", "project: {name: app, version: '1'}", false},
		{"escaped", "url: https://example.test/a%2fb", "project: {name: app, version: '1'}", false},
		{"http", "url: http://example.test", "project: {name: app, version: '1'}", false},
		{"explicit http", "url: http://example.test\nallowHTTP: true", "project: {name: app, version: '1'}", true},
		{"unknown", "url: https://example.test\napiKey: secret", "project: {name: app, version: '1'}", false},
		{"null", "url: null", "project: {name: app, version: '1'}", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, e := (Provider{}).Describe(node(t, tc.dst), node(t, tc.binding), delivery.Subject{Name: "subject", Version: "1"})
			if (e == nil) != tc.ok {
				t.Fatalf("%v", e)
			}
			if e != nil {
				if strings.Contains(e.Error(), "secret") {
					t.Fatal("leaked value")
				}
				return
			}
			b, _ := json.Marshal(d)
			if strings.Contains(string(b), "content-verification") {
				t.Fatal("unsupported capability")
			}
			if len(d.Capabilities) != 2 {
				t.Fatal(d)
			}
		})
	}
}
func TestDescribeMissingSubject(t *testing.T) {
	_, e := (Provider{}).Describe(node(t, "url: https://example.test"), node(t, "project: {fromSubject: true}"), delivery.Subject{Name: "app"})
	if e == nil {
		t.Fatal("missing subject version accepted")
	}
}

func TestPersistedDescriptionRejectsInventedCapabilities(t *testing.T) {
	d, e := (Provider{}).Describe(node(t, "url: https://example.test"), node(t, "project: {name: app, version: '1'}"), delivery.Subject{})
	if e != nil {
		t.Fatal(e)
	}
	d.Capabilities = append(d.Capabilities, "content-verification")
	if _, _, e = ValidateDescription(d); e == nil {
		t.Fatal("invented capability accepted")
	}
}

func TestPersistedSubmissionRequiresConsistentReceipt(t *testing.T) {
	for _, s := range []delivery.Submission{
		{Disposition: "accepted", References: []delivery.Reference{}, Observations: []delivery.Observation{}},
		{Disposition: "accepted", References: []delivery.Reference{{Kind: "dependency-track:event-token", Value: token}}, Observations: []delivery.Observation{{Kind: "acknowledgment", Value: "accepted", Origin: "receiver", Code: "accepted", HTTPStatus: 403, References: []delivery.Reference{}}}},
	} {
		if e := ValidateSubmission(s); e == nil {
			t.Fatal("contradictory receipt accepted")
		}
	}
}

func TestDescribeRejectsAPIEndpointAsBaseURL(t *testing.T) {
	for _, url := range []string{"https://example.test/api/v1", "https://example.test/prefix/api/v1/", "https://example.test/prefix/api/%761"} {
		if _, e := (Provider{}).Describe(node(t, "url: "+url), node(t, "project: {name: app, version: '1'}"), delivery.Subject{}); e == nil {
			t.Fatalf("API endpoint accepted as base: %s", url)
		}
	}
}
