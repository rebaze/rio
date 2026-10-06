package delivery

import (
	"testing"
)

func TestDecodeJSONNullableValueDoesNotRelaxTypedFields(t *testing.T) {
	var source Source
	for _, raw := range []string{`null`, `{"indexSHA256":null,"artifactId":"a","outputSHA256":"a","gate":"ok","schemaValidated":false,"allowFailedGate":false}`, `{"indexSHA256":"a","artifactId":"a","outputSHA256":"a","gate":"ok","schemaValidated":null,"allowFailedGate":false}`} {
		if e := DecodeJSON([]byte(raw), &source, true); e == nil {
			t.Fatal("required typed source accepted null")
		}
	}
	var description Description
	if e := DecodeJSON([]byte(`{"type":"test","destinationName":"x","identity":{},"options":{},"credentialRefs":null,"capabilities":[]}`), &description, true); e == nil {
		t.Fatal("required array accepted null")
	}
	var payload PayloadRef
	if e := DecodeJSON([]byte(`null`), &payload, true); e == nil {
		t.Fatal("null payload accepted")
	}
	var values struct {
		Before any `json:"before"`
		After  any `json:"after"`
	}
	if e := DecodeJSON([]byte(`{"before":null,"after":"value"}`), &values, true); e != nil {
		t.Fatal("nullable change refused", e)
	}
	if e := DecodeJSON([]byte(`{"after":"value"}`), &values, true); e == nil {
		t.Fatal("missing interface field accepted")
	}
}
