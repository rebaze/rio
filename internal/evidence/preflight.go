package evidence

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"

	"github.com/rebaze/rio/internal/delivery/record"
)

// preflightRecord visits the envelope without retaining an object tree or array
// elements. Count limits precede even tokenizing an excess element. Unknown and
// case-alias struct fields refuse before their possibly enormous values are read.
// The shared strict decoder still owns required fields, duplicate raw-object keys
// and detailed scalar/schema validation after these allocation bounds hold.
func preflightRecord(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	scan := recordScanner{dec: dec}
	if e := scan.value(reflect.TypeFor[Document](), "", 0); e != nil {
		return e
	}
	if _, e := dec.Token(); e != io.EOF {
		return invalid()
	}
	return nil
}

type recordScanner struct {
	dec          *json.Decoder
	events, refs int
}

var deliveriesType = reflect.TypeFor[[]Delivery]()
var sourcesType = reflect.TypeFor[[]SourceDocument]()
var eventsType = reflect.TypeFor[[]record.Event]()
var notesType = reflect.TypeFor[[]CollectionNote]()
var deliveryType = reflect.TypeFor[Delivery]()

func (s *recordScanner) value(t reflect.Type, scope string, depth int) error {
	if depth > 128 {
		return invalid()
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
	tok, e := s.dec.Token()
	if e != nil {
		return invalid()
	}
	if delim, ok := tok.(json.Delim); ok {
		switch delim {
		case '{':
			if t != nil && t.Kind() != reflect.Struct && t.Kind() != reflect.Map {
				return invalid()
			}
			seen := map[string]bool{}
			for s.dec.More() {
				key, e := s.dec.Token()
				if e != nil {
					return invalid()
				}
				name, ok := key.(string)
				if !ok {
					return invalid()
				}
				var child reflect.Type
				childScope := ""
				if t != nil && t.Kind() == reflect.Struct {
					for n := 0; n < t.NumField(); n++ {
						f := t.Field(n)
						if f.IsExported() && strings.Split(f.Tag.Get("json"), ",")[0] == name {
							child = f.Type
							break
						}
					}
					if child == nil || seen[name] {
						return invalid()
					}
					seen[name] = true
					if t == deliveryType && name == "evidenceIds" {
						childScope = "references"
					}
				}
				if e = s.value(child, childScope, depth+1); e != nil {
					return e
				}
			}
			if end, e := s.dec.Token(); e != nil || end != json.Delim('}') {
				return invalid()
			}
			return nil
		case '[':
			if t != nil && t.Kind() != reflect.Slice {
				return invalid()
			}
			count := 0
			limit := -1
			switch t {
			case deliveriesType:
				limit = MaxJournals
			case sourcesType:
				limit = MaxEvents + 1
			case eventsType:
				limit = MaxEvents
			case notesType:
				limit = MaxJournals
			}
			for s.dec.More() {
				if limit >= 0 && count >= limit {
					return limitError()
				}
				if t == eventsType {
					if s.events >= MaxEvents {
						return limitError()
					}
					s.events++
				}
				if scope == "references" {
					if s.refs >= MaxEvents {
						return limitError()
					}
					s.refs++
				}
				var child reflect.Type
				if t != nil {
					child = t.Elem()
				}
				if e = s.value(child, "", depth+1); e != nil {
					return e
				}
				count++
			}
			if end, e := s.dec.Token(); e != nil || end != json.Delim(']') {
				return invalid()
			}
			return nil
		default:
			return invalid()
		}
	}
	if t != nil {
		if tok == nil {
			return invalid()
		}
		switch t.Kind() {
		case reflect.Struct, reflect.Slice, reflect.Map:
			return invalid()
		case reflect.String:
			if _, ok := tok.(string); !ok {
				return invalid()
			}
		case reflect.Bool:
			if _, ok := tok.(bool); !ok {
				return invalid()
			}
		case reflect.Int, reflect.Int64:
			if _, ok := tok.(json.Number); !ok {
				return invalid()
			}
		}
	}
	return nil
}
