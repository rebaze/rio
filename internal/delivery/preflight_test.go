package delivery

import (
	"strings"
	"testing"
)

func TestPreflightJSONExactCollectionBudget(t *testing.T) {
	for _, count := range []int{10000, 10001} {
		raw := []byte("[" + strings.Repeat("0,", count-1) + "0]")
		var model []int
		e := PreflightJSON(raw, &model, 10000)
		if (e == nil) != (count == 10000) {
			t.Fatal(count, e)
		}
	}
}
func TestPreflightJSONRejectsUnknownBeforeValue(t *testing.T) {
	var model struct {
		Value string `json:"value"`
	}
	for _, raw := range []string{`{"Value":[not-json]}`, `{"unknown":[not-json]}`, `{"value":[]}`, `{"value":"a","value":"b"}`} {
		if e := PreflightJSON([]byte(raw), &model, 10000); e == nil {
			t.Fatal("malformed shape passed")
		}
	}
}
