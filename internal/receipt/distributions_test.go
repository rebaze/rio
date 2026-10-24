package receipt

import (
	"strings"
	"testing"
)

func withDistributions(d *Document, list ...Distribution) {
	d.Artifacts[0].Distributions = list
}

func TestDistributionsRoundTripAndAreOmittedWhenEmpty(t *testing.T) {
	d := fixture()
	raw, e := Marshal(d)
	if e != nil || strings.Contains(string(raw), "distributions") {
		t.Fatalf("empty distributions must be omitted: %v\n%s", e, raw)
	}
	withDistributions(&d, Distribution{Name: "app.tgz", SHA256: strings.Repeat("c", 64), Assertion: "producer"})
	raw, e = Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := Parse(raw)
	if e != nil || len(parsed.Artifacts[0].Distributions) != 1 || parsed.Artifacts[0].Distributions[0].Name != "app.tgz" {
		t.Fatalf("lost distributions: %v", e)
	}
}

func TestRejectInvalidDistributions(t *testing.T) {
	good := Distribution{Name: "app.tgz", SHA256: strings.Repeat("c", 64), Assertion: "producer"}
	tests := map[string][]Distribution{
		"blank name":       {{Name: " ", SHA256: good.SHA256, Assertion: "producer"}},
		"duplicate name":   {good, good},
		"short digest":     {{Name: "a", SHA256: "abc", Assertion: "producer"}},
		"uppercase digest": {{Name: "a", SHA256: strings.Repeat("C", 64), Assertion: "producer"}},
		"observed":         {{Name: "a", SHA256: good.SHA256, Assertion: "observed"}},
		"no assertion":     {{Name: "a", SHA256: good.SHA256}},
		"oversize name":    {{Name: strings.Repeat("n", MaxValueBytes+1), SHA256: good.SHA256, Assertion: "producer"}},
	}
	for name, list := range tests {
		t.Run(name, func(t *testing.T) {
			d := fixture()
			withDistributions(&d, list...)
			if _, e := Marshal(d); e == nil {
				t.Fatal("accepted invalid distributions")
			}
		})
	}
	t.Run("too many", func(t *testing.T) {
		d := fixture()
		for i := 0; i <= MaxItems; i++ {
			d.Artifacts[0].Distributions = append(d.Artifacts[0].Distributions, Distribution{Name: strings.Repeat("n", 1) + string(rune('a'+i%26)) + strings.Repeat("x", i/26), SHA256: good.SHA256, Assertion: "producer"})
		}
		if _, e := Marshal(d); e == nil {
			t.Fatal("accepted too many distributions")
		}
	})
}

func TestReportsListDistributions(t *testing.T) {
	d := fixture()
	sum := strings.Repeat("c", 64)
	withDistributions(&d, Distribution{Name: "app.tgz", SHA256: sum, Assertion: "producer"}, Distribution{Name: "app.zip", SHA256: strings.Repeat("d", 64), Assertion: "producer"})
	raw, e := Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	var text strings.Builder
	if e := Text(raw, &text); e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"2 distributions (producer assertion)", "app.tgz sha256=" + sum, "app.zip sha256="} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text lacks %q:\n%s", want, text.String())
		}
	}
	page, e := HTML(raw)
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"app.tgz", sum, "producer"} {
		if !strings.Contains(string(page), want) {
			t.Errorf("html lacks %q", want)
		}
	}
}
