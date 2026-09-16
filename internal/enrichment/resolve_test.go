package enrichment

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func ptr[T any](value T) *T { return &value }

func TestResolveOptionalAndExplicitEmpty(t *testing.T) {
	absent, err := Resolve(nil, nil, "artifacts[0]")
	if err != nil || absent != nil {
		t.Fatalf("absent = %+v, %v", absent, err)
	}
	empty, err := Resolve(&Config{}, nil, "artifacts[0]")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(empty)
	if string(raw) != `{"version":1,"fields":[]}` {
		t.Fatalf("empty = %s", raw)
	}
}

func TestResolveArrayOverridesAndIndependentOrganizationLeaves(t *testing.T) {
	defaults := &Config{Producer: &Organization{Name: ptr("Shared"), URL: ptr([]string{"https://shared.example"}), Contact: ptr([]Contact{{Name: ptr("Shared contact")}})}, Replace: ptr([]string{"producer.name"})}
	local := &Config{Producer: &Organization{URL: ptr([]string{}), Contact: ptr([]Contact{{Email: ptr("local@example.org")}})}, Replace: ptr([]string{"producer.contact"})}
	got, err := Resolve(defaults, local, "artifacts[3]")
	if err != nil {
		t.Fatal(err)
	}
	want := []Field{
		{Field: "producer.contact", Value: json.RawMessage(`[{"email":"local@example.org"}]`), Source: "artifacts[3].enrichment.producer.contact", Replace: true},
		{Field: "producer.name", Value: json.RawMessage(`"Shared"`), Source: "enrichment.producer.name"},
		{Field: "producer.url", Value: json.RawMessage(`[]`), Source: "artifacts[3].enrichment.producer.url"},
	}
	if !reflect.DeepEqual(got.Fields, want) {
		t.Fatalf("got %+v, want %+v", got.Fields, want)
	}
	if len(*defaults.Producer.URL) != 1 {
		t.Fatal("Resolve mutated defaults")
	}
}

func TestResolveChecksOverriddenValues(t *testing.T) {
	_, err := Resolve(&Config{Subject: &Subject{Name: ptr(" ")}}, &Config{Subject: &Subject{Name: ptr("Valid")}}, "artifacts[0]")
	if err == nil || !strings.Contains(err.Error(), "enrichment.subject.name") {
		t.Fatalf("error=%v", err)
	}
}

func TestResolveSecurityContactAndContacts(t *testing.T) {
	for _, value := range []string{"https://example.org/security", "mailto:security@example.org"} {
		if _, err := Resolve(nil, &Config{Subject: &Subject{SecurityContact: &value}}, "artifacts[0]"); err != nil {
			t.Errorf("%s: %v", value, err)
		}
	}
	for _, value := range []string{"https://user:secret@example.org/security", "mailto:person@example.org?subject=security", "mailto:Name <person@example.org>", "https://example.org/a b"} {
		if _, err := Resolve(nil, &Config{Subject: &Subject{SecurityContact: &value}}, "artifacts[0]"); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}

func TestResolveDeduplicatesOrganizationLists(t *testing.T) {
	defaults := &Config{Producer: &Organization{
		URL:     ptr([]string{"https://second.example", "https://first.example", "https://second.example", "https://first.example"}),
		Contact: ptr([]Contact{{Email: ptr("second@example.org")}, {Name: ptr("First"), Email: ptr("first@example.org")}, {Email: ptr("second@example.org")}, {Name: ptr("First"), Email: ptr("first@example.org")}, {Name: ptr("First")}}),
	}}
	for _, tt := range []struct {
		name            string
		defaults, local *Config
		source          string
	}{
		{"inherited", defaults, &Config{Subject: &Subject{Name: ptr("App")}}, "enrichment"},
		{"local", nil, defaults, "artifacts[2].enrichment"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resolved, err := Resolve(tt.defaults, tt.local, "artifacts[2]")
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range resolved.Fields {
				var want string
				switch field.Field {
				case "producer.url":
					want = `["https://second.example","https://first.example"]`
				case "producer.contact":
					want = `[{"email":"second@example.org"},{"name":"First","email":"first@example.org"},{"name":"First"}]`
				default:
					continue
				}
				if string(field.Value) != want || field.Source != tt.source+"."+field.Field {
					t.Errorf("field = %+v; want %s", field, want)
				}
			}
		})
	}
	if len(*defaults.Producer.URL) != 4 || len(*defaults.Producer.Contact) != 5 {
		t.Fatal("Resolve changed caller lists")
	}
}
