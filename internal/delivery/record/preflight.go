package record

import "github.com/rebaze/rio/internal/delivery"

// JSONEntryLimit applies before a committed event's collections are allocated.
// It bounds the combined object properties and array elements in one event.
const JSONEntryLimit = 10000

func preflight(raw []byte, model any) error {
	if int64(len(raw)) > EventLimit {
		return delivery.Fail("size_limit", "maximum event bytes")
	}
	if e := delivery.PreflightJSON(raw, model, JSONEntryLimit); e != nil {
		if safe, ok := e.(*delivery.Error); ok && safe.Code == "size_limit" {
			return e
		}
		return invalid()
	}
	return nil
}
