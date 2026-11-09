package enrichment

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
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

func link(label, url string, kind ...string) Link {
	l := Link{Label: ptr(label), URL: ptr(url)}
	if len(kind) > 0 {
		l.Type = ptr(kind[0])
	}
	return l
}

func TestResolveTypedLinkLeaves(t *testing.T) {
	got, err := Resolve(&Config{Subject: &Subject{
		IssueTracker: ptr("https://example.org/issues"),
		ReleaseNotes: ptr("https://example.org/releases"),
		Advisories:   ptr("https://example.org/advisories"),
	}}, nil, "artifacts[0]")
	if err != nil {
		t.Fatal(err)
	}
	want := []Field{
		{Field: "subject.advisories", Value: json.RawMessage(`"https://example.org/advisories"`), Source: "enrichment.subject.advisories"},
		{Field: "subject.issueTracker", Value: json.RawMessage(`"https://example.org/issues"`), Source: "enrichment.subject.issueTracker"},
		{Field: "subject.releaseNotes", Value: json.RawMessage(`"https://example.org/releases"`), Source: "enrichment.subject.releaseNotes"},
	}
	if !reflect.DeepEqual(got.Fields, want) {
		t.Fatalf("got %+v", got.Fields)
	}
	for _, s := range []*Subject{{IssueTracker: ptr("relative")}, {ReleaseNotes: ptr("ftp://example.org/x")}, {Advisories: ptr("https://u:p@example.org")}} {
		if _, err := Resolve(&Config{Subject: s}, nil, "artifacts[0]"); err == nil {
			t.Errorf("accepted %+v", s)
		}
	}
}

func TestResolveLinksMergePerLabel(t *testing.T) {
	defaults := &Config{Subject: &Subject{Links: ptr([]Link{
		link("Fact sheet", "https://ea.example/factsheet/shared"),
		link("Wiki", "https://wiki.example/app"),
	})}}
	local := &Config{
		Subject: &Subject{Links: ptr([]Link{
			link("Fact sheet", "https://ea.example/factsheet/console"),
			link("Threat model", "https://security.example/console", "threat-model"),
		})},
		Replace: ptr([]string{"subject.links[Fact sheet]"}),
	}
	got, err := Resolve(defaults, local, "artifacts[1]")
	if err != nil {
		t.Fatal(err)
	}
	want := []Field{
		{Field: "subject.links[Fact sheet]", Value: json.RawMessage(`{"url":"https://ea.example/factsheet/console","type":"other"}`), Source: "artifacts[1].enrichment.subject.links[Fact sheet]", Replace: true},
		{Field: "subject.links[Threat model]", Value: json.RawMessage(`{"url":"https://security.example/console","type":"threat-model"}`), Source: "artifacts[1].enrichment.subject.links[Threat model]"},
		{Field: "subject.links[Wiki]", Value: json.RawMessage(`{"url":"https://wiki.example/app","type":"other"}`), Source: "enrichment.subject.links[Wiki]"},
	}
	if diff := cmp.Diff(want, got.Fields); diff != "" {
		t.Fatal(diff)
	}
	if len(*defaults.Subject.Links) != 2 {
		t.Fatal("Resolve changed caller lists")
	}
}

func TestResolveRejectsInvalidLinks(t *testing.T) {
	for _, tt := range []struct {
		name  string
		links []Link
		want  string
	}{
		{"missing label", []Link{{URL: ptr("https://example.org")}}, "links[0].label: is required"},
		{"blank label", []Link{link("  ", "https://example.org")}, "links[0].label: must be a nonblank string"},
		{"bracket", []Link{link("a]b", "https://example.org")}, `links[0].label: must not contain "]"`},
		{"missing url", []Link{{Label: ptr("Fact sheet")}}, "links[0].url: is required"},
		{"relative url", []Link{link("Fact sheet", "factsheet/1")}, "links[0].url: must be an absolute HTTP(S) URL"},
		{"duplicate label", []Link{link("Fact sheet", "https://a.example"), link("Fact sheet", "https://b.example")}, `links[1].label: "Fact sheet" is listed more than once`},
		{"modeled type", []Link{link("Home", "https://example.org", "website")}, "links[0].type: website is modeled by enrichment.subject.website"},
		{"security type", []Link{link("Report", "https://example.org/security", "security-contact")}, "links[0].type: security-contact is modeled by enrichment.subject.securityContact"},
		{"blank type", []Link{link("Fact sheet", "https://example.org", " ")}, "links[0].type: must be a nonblank string"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Resolve(&Config{Subject: &Subject{Links: &tt.links}}, nil, "artifacts[0]")
			if err == nil || !strings.Contains(err.Error(), "enrichment.subject."+tt.want) {
				t.Fatalf("error = %v; want %q", err, tt.want)
			}
		})
	}
}

func TestResolveRejectsTheSameLinkUnderTwoLabels(t *testing.T) {
	defaults := &Config{Subject: &Subject{Links: ptr([]Link{link("Fact sheet", "https://ea.example/1")})}}
	local := &Config{Subject: &Subject{Links: ptr([]Link{link("Owner page", "https://ea.example/1")})}}
	_, err := Resolve(defaults, local, "artifacts[0]")
	if err == nil || !strings.Contains(err.Error(), `subject.links[Owner page] and subject.links[Fact sheet] declare the same type and URL`) {
		t.Fatalf("error = %v", err)
	}
}

func TestResolveLinkReplaceSelectors(t *testing.T) {
	config := func(replace ...string) *Config {
		return &Config{Subject: &Subject{Links: ptr([]Link{link("Fact sheet", "https://ea.example/1")})}, Replace: &replace}
	}
	if _, err := Resolve(config("subject.links[Fact sheet]"), nil, "artifacts[0]"); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ selector, want string }{
		{"subject.links[Owner page]", `field "subject.links[Owner page]" has no effective enrichment value`},
		{"subject.links", `unknown field "subject.links"`},
		{"subject.links[]", `unknown field "subject.links[]"`},
		{"subject.links[Fact sheet", `unknown field "subject.links[Fact sheet"`},
	} {
		if _, err := Resolve(config(tt.selector), nil, "artifacts[0]"); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: error = %v; want %q", tt.selector, err, tt.want)
		}
	}
}
