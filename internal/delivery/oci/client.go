package oci

import "github.com/rebaze/rio/internal/delivery"

// Build's explicit transport is completed by the following implementation task.
func (p Provider) Build(d delivery.Description, lookup func(string) (string, bool)) (delivery.Target, error) {
	if _, _, e := ValidateDescription(d); e != nil {
		return nil, e
	}
	return nil, delivery.Fail("unsupported_operation", "OCI transport not yet available")
}
