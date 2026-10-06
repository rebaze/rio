package record

import "github.com/rebaze/rio/internal/delivery"

func preflight(raw []byte, model any) error {
	if int64(len(raw)) > EventLimit {
		return delivery.Fail("size_limit", "maximum event bytes")
	}
	if e := delivery.PreflightJSON(raw, model); e != nil {
		if safe, ok := e.(*delivery.Error); ok && safe.Code == "size_limit" {
			return e
		}
		return invalid()
	}
	return nil
}
