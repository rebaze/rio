package evidence

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

func canonicalJSON(raw []byte) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if e := dec.Decode(&v); e != nil {
		return nil, invalid()
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if e := enc.Encode(v); e != nil {
		return nil, invalid()
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}
func jsonEqual(a, b []byte) bool {
	aa, e := canonicalJSON(a)
	if e != nil {
		return false
	}
	bb, e := canonicalJSON(b)
	return e == nil && bytes.Equal(aa, bb)
}

// Marshal measures the complete encoding before the final buffer is allocated.
// The budget includes base64, repeated readable projections and the final LF.
func Marshal(d Document) ([]byte, error) {
	if d.SchemaVersion != 1 || d.Kind != "rio-evidence-record" || d.Tool.Name != "rio" || d.Tool.Version == "" {
		return nil, invalid()
	}
	if encodedSize(reflect.ValueOf(d))+1 > FileLimit {
		return nil, limitError()
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if e := enc.Encode(d); e != nil {
		return nil, invalid()
	}
	if int64(b.Len()) > FileLimit {
		return nil, limitError()
	}
	return b.Bytes(), nil
}

var rawType = reflect.TypeFor[json.RawMessage]()

func encodedSize(v reflect.Value) int64 {
	if !v.IsValid() {
		return 4
	}
	if v.Type() == rawType {
		return int64(v.Len())
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return 4
		}
		return encodedSize(v.Elem())
	case reflect.String:
		return stringSize(v.String())
	case reflect.Bool:
		return 5
	case reflect.Int, reflect.Int64:
		return int64(len(strconv.FormatInt(v.Int(), 10)))
	case reflect.Slice:
		if v.IsNil() {
			return 4
		}
		n := int64(2)
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				n++
			}
			n += encodedSize(v.Index(i))
			if n > FileLimit {
				return n
			}
		}
		return n
	case reflect.Struct:
		n := int64(2)
		count := 0
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			tag := strings.Split(t.Field(i).Tag.Get("json"), ",")
			if tag[0] == "-" {
				continue
			}
			f := v.Field(i)
			if len(tag) > 1 && tag[1] == "omitempty" && f.IsZero() {
				continue
			}
			if count > 0 {
				n++
			}
			count++
			n += stringSize(tag[0]) + 1 + encodedSize(f)
			if n > FileLimit {
				return n
			}
		}
		return n
	default:
		return FileLimit + 1
	}
}
func stringSize(s string) int64 {
	n := int64(2)
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		s = s[size:]
		switch {
		case r == '"' || r == '\\' || r == '\b' || r == '\f' || r == '\n' || r == '\r' || r == '\t':
			n += 2
		case r < 32 || r == 0x2028 || r == 0x2029:
			n += 6
		case r == utf8.RuneError && size == 1:
			n += 6
		default:
			n += int64(size)
		}
	}
	return n
}
