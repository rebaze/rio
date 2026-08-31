package index_test

import (
	"encoding/json"
	"testing"

	"github.com/rebaze/rio/internal/index"
)

// FuzzGateUnmarshalJSON drives gate decoding with arbitrary JSON.
//
// The invariant is the one the method exists to hold: rio record reads this
// field back, and an unrecognised gate must never decode into something a
// consumer could read as a pass. Either the input is one of the two known
// values, or unmarshalling fails.
func FuzzGateUnmarshalJSON(f *testing.F) {
	f.Add([]byte(`"ok"`))
	f.Add([]byte(`"fail"`))
	f.Add([]byte(`""`))
	f.Add([]byte(`"OK"`))
	f.Add([]byte(`"warn"`))
	f.Add([]byte(`null`))
	f.Add([]byte(`0`))
	f.Add([]byte(`{"gate":"ok"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var g index.Gate
		if err := g.UnmarshalJSON(data); err != nil {
			return
		}
		if !g.Valid() {
			t.Fatalf("decoded %q into the invalid gate %q", data, string(g))
		}
		// Whatever decoded has to survive being written back out, since the
		// index is re-read by rio record.
		out, err := json.Marshal(g)
		if err != nil {
			t.Fatalf("gate %q decoded but will not marshal: %v", string(g), err)
		}
		var again index.Gate
		if err := again.UnmarshalJSON(out); err != nil {
			t.Fatalf("gate %q did not survive a round trip: %v", string(g), err)
		}
		if again != g {
			t.Fatalf("gate changed across a round trip: %q became %q", string(g), string(again))
		}
	})
}
