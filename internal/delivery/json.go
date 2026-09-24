package delivery

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
)

// DecodeJSON rejects duplicate keys and trailing documents, then validates all
// required struct fields, including explicit false/zero and non-null arrays.
// Unknown additive fields remain compatible unless strict is requested.
func DecodeJSON(b []byte, out any, strict bool) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	value, err := jsonValue(d, 0)
	if err != nil {
		return Fail("invalid_json", "document")
	}
	if _, err = d.Token(); err != io.EOF {
		return Fail("invalid_json", "trailing document")
	}
	if err = shape(value, reflect.TypeOf(out).Elem(), strict); err != nil {
		return err
	}
	// encoding/json accepts case-insensitive aliases. Bind only exact tagged keys
	// from the validated tree so additive fields cannot overwrite contract fields.
	exact, marshalErr := json.Marshal(exactJSONValue(value, reflect.TypeOf(out).Elem()))
	if marshalErr != nil || json.Unmarshal(exact, out) != nil {
		return Fail("invalid_json", "field type")
	}
	return nil
}
func jsonValue(d *json.Decoder, depth int) (any, error) {
	if depth > 128 {
		return nil, Fail("invalid_json", "nesting limit")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	switch delim {
	case '{':
		m := map[string]any{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return nil, e
			}
			s, ok := k.(string)
			if !ok {
				return nil, io.ErrUnexpectedEOF
			}
			if _, ok = m[s]; ok {
				return nil, Fail("invalid_json", "duplicate key")
			}
			v, e := jsonValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			m[s] = v
		}
		_, err = d.Token()
		return m, err
	case '[':
		a := []any{}
		for d.More() {
			v, e := jsonValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		_, err = d.Token()
		return a, err
	}
	return nil, io.ErrUnexpectedEOF
}

var rawType = reflect.TypeFor[json.RawMessage]()

func shape(v any, t reflect.Type, strict bool) error {
	if v == nil {
		return Fail("invalid_json", "null field")
	}
	if t == rawType {
		return nil
	}
	if t.Kind() == reflect.Pointer {
		return shape(v, t.Elem(), strict)
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return Fail("invalid_json", "object required")
		}
		known := map[string]bool{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			tag := strings.Split(f.Tag.Get("json"), ",")
			k := tag[0]
			if k == "-" {
				continue
			}
			known[k] = true
			item, exists := m[k]
			optional := len(tag) > 1 && tag[1] == "omitempty"
			if !exists {
				if optional {
					continue
				}
				return Fail("invalid_json", "missing "+k)
			}
			if err := shape(item, f.Type, strict); err != nil {
				return err
			}
		}
		if strict {
			for k := range m {
				if !known[k] {
					return Fail("invalid_json", "unknown field")
				}
			}
		}
	case reflect.Slice:
		a, ok := v.([]any)
		if !ok {
			return Fail("invalid_json", "array required")
		}
		for _, x := range a {
			if err := shape(x, t.Elem(), strict); err != nil {
				return err
			}
		}
	}
	return nil
}

// JSONEqual compares validated JSON identities independently of record indentation.
func JSONEqual(a, b json.RawMessage) bool {
	var av, bv any
	if DecodeJSON(a, &av, false) != nil || DecodeJSON(b, &bv, false) != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

func exactJSONValue(v any, t reflect.Type) any {
	if t == rawType {
		return v
	}
	if t.Kind() == reflect.Pointer {
		return exactJSONValue(v, t.Elem())
	}
	switch t.Kind() {
	case reflect.Struct:
		source := v.(map[string]any)
		result := map[string]any{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			key := strings.Split(f.Tag.Get("json"), ",")[0]
			if item, ok := source[key]; ok {
				result[key] = exactJSONValue(item, f.Type)
			}
		}
		return result
	case reflect.Slice:
		source := v.([]any)
		result := make([]any, len(source))
		for i, item := range source {
			result[i] = exactJSONValue(item, t.Elem())
		}
		return result
	default:
		return v
	}
}
