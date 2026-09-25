package delivery

// PreflightJSON checks the declared schema using the same typed streaming path
// as DecodeJSON, without retaining struct/slice values. It adds no entry limit
// to the caller's existing byte and schema contracts.
func PreflightJSON(raw []byte, model any) error { return decodeJSON(raw, model, true, false) }
