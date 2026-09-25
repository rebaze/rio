package dtrack

import (
	"encoding/json"
	"strings"

	"github.com/rebaze/rio/internal/delivery"
)

// TLSFacts describe configured verification and an observed successful TLS
// handshake. Disabled verification makes no assertion about certificate validity.
// No peer certificate, key, or transport error is retained.
type TLSFacts struct {
	CertificateVerification string `json:"certificateVerification"`
	Observed                bool   `json:"observed"`
}
type transportDetails struct {
	TLS *TLSFacts `json:"tls,omitempty"`
}

func (c *client) addTLS(o *delivery.Observation, observed bool) {
	if !strings.HasPrefix(c.options.URL, "https://") {
		return
	}
	verification := "enforced"
	if c.options.InsecureSkipVerify {
		verification = "disabled"
	}
	o.Details, _ = json.Marshal(transportDetails{TLS: &TLSFacts{verification, observed}})
}

// ReadTLS validates the complete adapter-owned detail without interpreting old
// absent details as observed transport evidence.
func ReadTLS(o delivery.Observation) (*TLSFacts, error) {
	if o.Details == nil {
		return nil, nil
	}
	var d transportDetails
	if delivery.DecodeJSON(o.Details, &d, true) != nil {
		return nil, delivery.Fail("invalid_record", "Dependency-Track TLS details")
	}
	if d.TLS != nil && d.TLS.CertificateVerification != "enforced" && d.TLS.CertificateVerification != "disabled" {
		return nil, delivery.Fail("invalid_record", "Dependency-Track TLS verification policy")
	}
	return d.TLS, nil
}

// ValidateTransport binds transport observations to the immutable intent. Old
// verified-mode histories may lack TLS details; absence remains not-recorded.
func ValidateTransport(d delivery.Description, observations []delivery.Observation) error {
	options, _, err := ValidateDescription(d)
	if err != nil {
		return err
	}
	https := strings.HasPrefix(options.URL, "https://")
	verification := "enforced"
	if options.InsecureSkipVerify {
		verification = "disabled"
	}
	for _, o := range observations {
		facts, err := ReadTLS(o)
		if err != nil {
			return err
		}
		if facts == nil {
			if options.InsecureSkipVerify {
				return delivery.Fail("invalid_record", "explicit TLS bypass evidence missing")
			}
			continue
		}
		if !https || facts.CertificateVerification != verification || (o.Origin == "receiver" && !facts.Observed) || (o.Code == "missing_reference" && facts.Observed) {
			return delivery.Fail("invalid_record", "Dependency-Track TLS evidence contradicts intent or observation")
		}
	}
	return nil
}
