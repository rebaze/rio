package delivery

import (
	"encoding/json"
	"testing"
)

func TestJSONStringDecodingPreservesEscapesAndReplacement(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`"plain"`), []byte(`"caf\u00e9"`), []byte(`"\ud83d\ude80"`), []byte(`"\ud800x"`), []byte(`"\udc00"`), []byte(`"\\\"\/\b\f\n\r\t"`), {'"', 0xff, '"'}} {
		var want string
		if e := json.Unmarshal(raw, &want); e != nil {
			t.Fatal(e)
		}
		var got string
		if e := DecodeJSON(raw, &got, true); e != nil || got != want {
			t.Fatalf("string semantics %q got=%q want=%q err=%v", raw, got, want, e)
		}
		encoded, _ := json.Marshal(want)
		if !JSONEqual(raw, encoded) {
			t.Fatalf("string comparison changed for %q", raw)
		}
		object := append(append([]byte{'{'}, raw...), []byte(`:true}`)...)
		var mapping map[string]bool
		if e := DecodeJSON(object, &mapping, true); e != nil || !mapping[want] {
			t.Fatalf("key semantics %q: %v", raw, e)
		}
	}
}
