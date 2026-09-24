package dtrack

import (
	"github.com/rebaze/rio/internal/delivery"
	"gopkg.in/yaml.v3"
	"testing"
)

func TestDescribeUnifiedDefaults(t *testing.T) {
	for _, tc := range []struct {
		target, override string
		ok               bool
	}{
		{"url: https://EXAMPLE.test:443", "{}", true},
		{"url: https://example.test\nautoCreate: false", "project: {uuid: f90934f5-cb88-47ce-81cb-db06fc67d4b4}", false},
		{"url: https://example.test", "project: {uuid: f90934f5-cb88-47ce-81cb-db06fc67d4b4}", true},
		{"url: https://example.test\nproject: {name: app, version: 1}", "{}", false},
	} {
		var a, b yaml.Node
		yaml.Unmarshal([]byte(tc.target), &a)
		yaml.Unmarshal([]byte(tc.override), &b)
		d, e := (Provider{}).Describe(*a.Content[0], *b.Content[0], delivery.Subject{Name: "subject", Version: "1"})
		if (e == nil) != tc.ok {
			t.Fatalf("%s: %v", tc.target, e)
		}
		if e == nil {
			if _, _, e := ValidateDescription(d); e != nil {
				t.Fatal(e)
			}
		}
	}
}
