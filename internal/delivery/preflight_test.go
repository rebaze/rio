package delivery

import (
	"strings"
	"testing"
)

func TestPreflightJSONPreservesByteBoundedCollections(t *testing.T) {
	for _, count := range []int{10000, 10001} {
		raw := []byte("[" + strings.Repeat("0,", count-1) + "0]")
		var model []int
		e := PreflightJSON(raw, &model)
		if e != nil {
			t.Fatal(count, e)
		}
	}
}
func TestPreflightJSONRejectsUnknownBeforeValue(t *testing.T) {
	var model struct {
		Value string `json:"value"`
	}
	for _, raw := range []string{`{"Value":[not-json]}`, `{"unknown":[not-json]}`, `{"value":[]}`, `{"value":"a","value":"b"}`} {
		if e := PreflightJSON([]byte(raw), &model); e == nil {
			t.Fatal("malformed shape passed")
		}
	}
}
