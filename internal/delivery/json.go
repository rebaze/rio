package delivery

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
)

// DecodeJSON validates and binds one value directly into its declared type.
// Opaque RawMessage values retain their bytes, not a generic object/array tree.
// Array elements are validated before append; unknown strict keys fail before
// their value is visited. Byte limits belong to the caller's existing contract.
func DecodeJSON(raw []byte, out any, strict bool) error { return decodeJSON(raw, out, strict, true) }
func decodeJSON(raw []byte, out any, strict, retain bool) error {
	target := reflect.ValueOf(out)
	if target.Kind() != reflect.Pointer || target.IsNil() {
		return Fail("invalid_json", "decode target")
	}
	if !json.Valid(raw) {
		return Fail("invalid_json", "document")
	}
	r := jsonReader{raw: raw}
	var value reflect.Value
	if retain {
		value = reflect.New(target.Elem().Type()).Elem()
	}
	if e := r.value(target.Elem().Type(), value, strict, 0); e != nil {
		return e
	}
	r.space()
	if r.pos != len(raw) {
		return Fail("invalid_json", "trailing document")
	}
	if retain {
		target.Elem().Set(value)
	}
	return nil
}

var rawType = reflect.TypeFor[json.RawMessage]()

type jsonField struct {
	index    int
	typ      reflect.Type
	optional bool
}
type jsonFields struct{ named map[string]jsonField }

var jsonFieldCache sync.Map

func fieldsFor(t reflect.Type) *jsonFields {
	if cached, ok := jsonFieldCache.Load(t); ok {
		return cached.(*jsonFields)
	}
	fields := &jsonFields{named: map[string]jsonField{}}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := strings.Split(f.Tag.Get("json"), ",")
		if tag[0] == "-" {
			continue
		}
		fields.named[tag[0]] = jsonField{i, f.Type, len(tag) > 1 && tag[1] == "omitempty"}
	}
	actual, _ := jsonFieldCache.LoadOrStore(t, fields)
	return actual.(*jsonFields)
}

type jsonReader struct {
	raw []byte
	pos int
}

func (r *jsonReader) space() {
	for r.pos < len(r.raw) {
		switch r.raw[r.pos] {
		case ' ', '\n', '\r', '\t':
			r.pos++
		default:
			return
		}
	}
}
func (r *jsonReader) quoted() []byte {
	start := r.pos
	r.pos++
	for {
		c := r.raw[r.pos]
		r.pos++
		if c == '\\' {
			r.pos++
			continue
		}
		if c == '"' {
			return r.raw[start:r.pos]
		}
	}
}
func (r *jsonReader) key() string {
	r.space()
	raw := r.quoted()
	var s string
	_ = json.Unmarshal(raw, &s)
	r.space()
	r.pos++
	return s
}
func (r *jsonReader) primitive() {
	if r.raw[r.pos] == '"' {
		r.quoted()
		return
	}
	for r.pos < len(r.raw) {
		switch r.raw[r.pos] {
		case ',', ']', '}', ' ', '\r', '\n', '\t':
			return
		default:
			r.pos++
		}
	}
}

// skip checks duplicate keys/depth using byte offsets. It allocates no array
// entries (including an arbitrarily long array of empty objects).
func (r *jsonReader) skip(depth int) error {
	if depth > 128 {
		return Fail("invalid_json", "nesting limit")
	}
	r.space()
	switch r.raw[r.pos] {
	case '{':
		r.pos++
		r.space()
		var seen map[string]bool
		for r.raw[r.pos] != '}' {
			key := r.key()
			if seen[key] {
				return Fail("invalid_json", "duplicate key")
			}
			if seen == nil {
				seen = map[string]bool{}
			}
			seen[key] = true
			if e := r.skip(depth + 1); e != nil {
				return e
			}
			r.space()
			if r.raw[r.pos] == ',' {
				r.pos++
				r.space()
			} else {
				break
			}
		}
		r.pos++
	case '[':
		r.pos++
		r.space()
		for r.raw[r.pos] != ']' {
			if e := r.skip(depth + 1); e != nil {
				return e
			}
			r.space()
			if r.raw[r.pos] == ',' {
				r.pos++
				r.space()
			} else {
				break
			}
		}
		r.pos++
	default:
		r.primitive()
	}
	return nil
}
func (r *jsonReader) value(t reflect.Type, v reflect.Value, strict bool, depth int) error {
	if depth > 128 {
		return Fail("invalid_json", "nesting limit")
	}
	r.space()
	start := r.pos
	if r.raw[r.pos] == 'n' && t.Kind() != reflect.Interface {
		return Fail("invalid_json", "null field")
	}
	if t == rawType {
		if e := r.skip(depth); e != nil {
			return e
		}
		if v.IsValid() {
			v.SetBytes(bytes.Clone(r.raw[start:r.pos]))
		}
		return nil
	}
	if t.Kind() == reflect.Pointer {
		var child reflect.Value
		if v.IsValid() {
			v.Set(reflect.New(t.Elem()))
			child = v.Elem()
		}
		return r.value(t.Elem(), child, strict, depth)
	}
	switch t.Kind() {
	case reflect.Struct:
		if r.raw[r.pos] != '{' {
			return Fail("invalid_json", "object required")
		}
		r.pos++
		r.space()
		fields := fieldsFor(t)
		seen := map[string]bool{}
		for r.raw[r.pos] != '}' {
			key := r.key()
			if seen[key] {
				return Fail("invalid_json", "duplicate key")
			}
			seen[key] = true
			field, known := fields.named[key]
			if !known {
				if strict {
					return Fail("invalid_json", "unknown field")
				}
				if e := r.skip(depth + 1); e != nil {
					return e
				}
			} else {
				var child reflect.Value
				if v.IsValid() {
					child = v.Field(field.index)
				}
				if e := r.value(field.typ, child, strict, depth+1); e != nil {
					return e
				}
			}
			r.space()
			if r.raw[r.pos] == ',' {
				r.pos++
				r.space()
			} else {
				break
			}
		}
		r.pos++
		for name, field := range fields.named {
			if !field.optional && !seen[name] {
				return Fail("invalid_json", "missing "+name)
			}
		}
		return nil
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			break
		}
		if r.raw[r.pos] != '[' {
			return Fail("invalid_json", "array required")
		}
		r.pos++
		r.space()
		if v.IsValid() {
			v.Set(reflect.MakeSlice(t, 0, 0))
		}
		for r.raw[r.pos] != ']' {
			var child reflect.Value
			if v.IsValid() {
				child = reflect.New(t.Elem()).Elem()
			}
			if e := r.value(t.Elem(), child, strict, depth+1); e != nil {
				return e
			}
			if v.IsValid() {
				v.Set(reflect.Append(v, child))
			}
			r.space()
			if r.raw[r.pos] == ',' {
				r.pos++
				r.space()
			} else {
				break
			}
		}
		r.pos++
		return nil
	case reflect.Map:
		// Preserve native map-value decoding semantics. In particular RawMessage
		// map values stay opaque; their adapter subsequently applies its schema.
		if r.raw[r.pos] != '{' {
			return Fail("invalid_json", "object required")
		}
	}
	if e := r.skip(depth); e != nil {
		return e
	}
	if !v.IsValid() {
		if t.Kind() == reflect.Map || t.Kind() == reflect.Interface {
			return nil
		}
		v = reflect.New(t).Elem()
	}
	dec := json.NewDecoder(bytes.NewReader(r.raw[start:r.pos]))
	dec.UseNumber()
	if e := dec.Decode(v.Addr().Interface()); e != nil {
		return Fail("invalid_json", "field type")
	}
	return nil
}

// JSONEqual preserves number tokens and compares validated JSON values.
func JSONEqual(a, b json.RawMessage) bool {
	var av, bv any
	if DecodeJSON(a, &av, false) != nil || DecodeJSON(b, &bv, false) != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

// ValidateJSON checks syntax, duplicate keys and nesting without materializing
// generic maps/arrays. It is useful for opaque adapter-owned JSON regions.
func ValidateJSON(raw []byte) error {
	if !json.Valid(raw) {
		return Fail("invalid_json", "document")
	}
	r := jsonReader{raw: raw}
	return r.skip(0)
}
