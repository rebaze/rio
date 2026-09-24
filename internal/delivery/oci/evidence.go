package oci

import "github.com/rebaze/rio/internal/delivery/record"

// The publication and observer tasks extend this validator with their owned schemas.
func ValidateSnapshot(s record.Snapshot) error {
	if e := ValidateIntent(s.Intent); e != nil {
		return e
	}
	if len(s.Events) != 1 || len(s.Observations) != 0 || len(s.References) != 0 || s.Disposition != "unknown" {
		return invalid("unsupported OCI evidence")
	}
	return nil
}
