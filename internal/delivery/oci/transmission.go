package oci

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/rebaze/rio/internal/delivery"
)

type TLSFacts struct {
	CertificateVerification string `json:"certificateVerification"`
	Observed                bool   `json:"observed"`
}

func (c *client) addTLS(ctx context.Context, o *delivery.Observation) {
	if c.options.AllowHTTP {
		return
	}
	var d details
	if json.Unmarshal(o.Details, &d) != nil {
		return
	}
	state := ctx.Value(traversalKey{}).(*traversalState)
	state.mu.Lock()
	observed := state.tlsObserved
	state.mu.Unlock()
	d.TLS = &TLSFacts{CertificateVerification: "enforced", Observed: observed}
	o.Details, _ = json.Marshal(d)
}
func ReadTLS(o delivery.Observation) (*TLSFacts, error) {
	if o.Details == nil {
		return nil, nil
	}
	var d details
	if e := delivery.DecodeJSON(o.Details, &d, true); e != nil {
		return nil, e
	}
	if d.TLS != nil && d.TLS.CertificateVerification != "enforced" {
		return nil, invalid("TLS policy")
	}
	return d.TLS, nil
}

// PublicationBodies describes potential request bodies without including their
// content. An existing blob/manifest may be reused instead of transmitted.
func PublicationBodies(d delivery.Description) ([]delivery.PayloadRef, error) {
	o, _, e := ValidateDescription(d)
	if e != nil {
		return nil, e
	}
	if o.Publication == nil {
		return nil, invalid("prepared publication required")
	}
	return publicationBodies(o), nil
}
func publicationBodies(o Options) []delivery.PayloadRef {
	p := o.Publication
	source := p.Payload.SourceSHA256
	sbom := p.Payload
	sbom.MediaType = "application/octet-stream"
	return []delivery.PayloadRef{
		{Role: "oci-config", MediaType: "application/octet-stream", SHA256: strings.TrimPrefix(p.Config.Digest, "sha256:"), Size: p.Config.Size, SourceSHA256: source, Transformation: "oci-config"},
		sbom,
		{Role: "oci-manifest", MediaType: p.Manifest.MediaType, SHA256: strings.TrimPrefix(p.Manifest.Digest, "sha256:"), Size: p.Manifest.Size, SourceSHA256: source, Transformation: "oci-manifest"},
	}
}
