package delivery

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
)

// PreflightJSON bounds collection entries before retaining their object/array
// tree. Strict typed keys and scalar shapes are checked before visiting values.
// RawMessage bodies remain adapter-owned but share the same allocation budget.
func PreflightJSON(raw []byte, model any, maxEntries int) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	entries := 0
	var visit func(reflect.Type, int) error
	visit = func(t reflect.Type, depth int) error {
		if depth > 128 {
			return Fail("invalid_json", "nesting limit")
		}
		if t == rawType {
			t = nil
		}
		if t != nil && t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if t != nil && t.Kind() == reflect.Interface {
			t = nil
		}
		tok, e := d.Token()
		if e != nil {
			return Fail("invalid_json", "document")
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				if t != nil && t.Kind() != reflect.Struct && t.Kind() != reflect.Map {
					return Fail("invalid_json", "object type")
				}
				seen := map[string]bool{}
				for d.More() {
					if entries >= maxEntries {
						return Fail("size_limit", "maximum JSON collection entries")
					}
					entries++
					tok, e = d.Token()
					key, ok := tok.(string)
					if e != nil || !ok || seen[key] {
						return Fail("invalid_json", "object key")
					}
					seen[key] = true
					var child reflect.Type
					if t != nil {
						if t.Kind() == reflect.Map {
							child = t.Elem()
						} else {
							for i := 0; i < t.NumField(); i++ {
								f := t.Field(i)
								if f.IsExported() && strings.Split(f.Tag.Get("json"), ",")[0] == key {
									child = f.Type
									break
								}
							}
							if child == nil {
								return Fail("invalid_json", "unknown field")
							}
						}
					}
					if e = visit(child, depth+1); e != nil {
						return e
					}
				}
				tok, e = d.Token()
				if e != nil || tok != json.Delim('}') {
					return Fail("invalid_json", "object end")
				}
			case '[':
				if t != nil && t.Kind() != reflect.Slice {
					return Fail("invalid_json", "array type")
				}
				for d.More() {
					if entries >= maxEntries {
						return Fail("size_limit", "maximum JSON collection entries")
					}
					entries++
					var child reflect.Type
					if t != nil {
						child = t.Elem()
					}
					if e = visit(child, depth+1); e != nil {
						return e
					}
				}
				tok, e = d.Token()
				if e != nil || tok != json.Delim(']') {
					return Fail("invalid_json", "array end")
				}
			default:
				return Fail("invalid_json", "delimiter")
			}
			return nil
		}
		if t == nil {
			return nil
		}
		if tok == nil {
			return Fail("invalid_json", "null field")
		}
		switch t.Kind() {
		case reflect.Struct, reflect.Map, reflect.Slice:
			return Fail("invalid_json", "object or array required")
		case reflect.String:
			if _, ok := tok.(string); !ok {
				return Fail("invalid_json", "string required")
			}
		case reflect.Bool:
			if _, ok := tok.(bool); !ok {
				return Fail("invalid_json", "boolean required")
			}
		case reflect.Int, reflect.Int64:
			if _, ok := tok.(json.Number); !ok {
				return Fail("invalid_json", "integer required")
			}
		}
		return nil
	}
	if e := visit(reflect.TypeOf(model), 0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return Fail("invalid_json", "trailing document")
	}
	return nil
}
