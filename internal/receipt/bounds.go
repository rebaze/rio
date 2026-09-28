package receipt

import (
	"bytes"
	"encoding/json"
	"github.com/rebaze/rio/internal/delivery"
	"io"
)

const (
	MaxDepth       = 64
	MaxStringBytes = 16 << 10
	MaxJSONNodes   = 250000
)

// boundJSON walks tokens before typed decoding can retain a large collection.
// Limits apply equally to parsing and publication, including opaque metadata.
func boundJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	nodes := 0
	var value func(int) error
	value = func(depth int) error {
		if depth > MaxDepth {
			return delivery.Fail("size_limit", "receipt nesting limit")
		}
		nodes++
		if nodes > MaxJSONNodes {
			return delivery.Fail("size_limit", "receipt JSON node limit")
		}
		token, e := dec.Token()
		if e != nil {
			return invalid("JSON syntax")
		}
		if s, ok := token.(string); ok && len(s) > MaxStringBytes {
			return delivery.Fail("size_limit", "receipt string byte limit")
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{', '[':
			count := 0
			for dec.More() {
				count++
				if count > MaxItems {
					return delivery.Fail("size_limit", "receipt collection item limit")
				}
				if delimiter == '{' {
					key, e := dec.Token()
					if e != nil {
						return invalid("JSON key")
					}
					s, ok := key.(string)
					if !ok || len(s) > MaxStringBytes {
						return delivery.Fail("size_limit", "receipt key byte limit")
					}
				}
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			end, e := dec.Token()
			if e != nil || delimiter == '{' && end != json.Delim('}') || delimiter == '[' && end != json.Delim(']') {
				return invalid("JSON delimiter")
			}
		default:
			return invalid("JSON delimiter")
		}
		return nil
	}
	if e := value(0); e != nil {
		return e
	}
	if _, e := dec.Token(); e != io.EOF {
		return invalid("trailing JSON")
	}
	return nil
}
