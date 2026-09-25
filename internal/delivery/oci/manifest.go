package oci

import (
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"reflect"
	"strings"
)

const emptyConfig = "{}"
const indexAnnotation = "io.rebaze.rio.index.sha256"

type Publication struct {
	ManifestJSON string              `json:"manifestJSON"`
	Manifest     Descriptor          `json:"manifest"`
	Config       Descriptor          `json:"config"`
	Payload      delivery.PayloadRef `json:"payload"`
	Tag          string              `json:"tag"`
	Subject      *Descriptor         `json:"subject,omitempty"`
}
type layer struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations"`
}
type envelope struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType"`
	Config        Descriptor        `json:"config"`
	Layers        []layer           `json:"layers"`
	Subject       *Descriptor       `json:"subject,omitempty"`
	Annotations   map[string]string `json:"annotations"`
}

func packageManifest(o Options, indexDigest string, p delivery.PayloadRef) Publication {
	c := Descriptor{EmptyMediaType, "sha256:" + delivery.Digest([]byte(emptyConfig)), int64(len(emptyConfig))}
	m := envelope{2, ManifestMediaType, SBOMMediaType, c, []layer{{SBOMMediaType, "sha256:" + p.SHA256, p.Size, map[string]string{"org.opencontainers.image.title": "sbom.cdx.json"}}}, o.Subject, map[string]string{indexAnnotation: indexDigest}}
	b := mustJSON(m)
	digest := delivery.Digest(b)
	return Publication{string(b), Descriptor{ManifestMediaType, "sha256:" + digest, int64(len(b))}, c, p, "rio-sbom-sha256-" + digest, o.Subject}
}
func validPayload(p delivery.PayloadRef) bool {
	return p.Role == "sbom" && p.MediaType == SBOMMediaType && p.Transformation == "identity" && delivery.ValidDigest(p.SHA256) && p.SHA256 == p.SourceSHA256 && p.Size > 0 && p.Size <= delivery.PayloadLimit
}
func validatePublication(o Options) error {
	pub := o.Publication
	if pub == nil || !validPayload(pub.Payload) || int64(len(pub.ManifestJSON)) > DocumentLimit {
		return invalid("publication")
	}
	// The full canonical byte comparison below is the validation. Extract only
	// the fixed source-digest token; never decode attacker-supplied layer arrays.
	marker := `"` + indexAnnotation + `":"`
	offset := strings.Index(pub.ManifestJSON, marker)
	if offset < 0 {
		return invalid("publication source digest")
	}
	offset += len(marker)
	if len(pub.ManifestJSON) < offset+65 || pub.ManifestJSON[offset+64] != '"' {
		return invalid("publication source digest")
	}
	hash := pub.ManifestJSON[offset : offset+64]
	if !delivery.ValidDigest(hash) {
		return invalid("publication source digest")
	}
	want := packageManifest(o, hash, pub.Payload)
	if !reflect.DeepEqual(*pub, want) {
		return invalid("noncanonical publication")
	}
	return nil
}
func expected(o Options) []delivery.Reference {
	p := o.Publication
	base := o.Registry + "/" + o.Repository
	refs := []delivery.Reference{{Kind: "oci:manifest", Value: base + "@" + p.Manifest.Digest}, {Kind: "oci:blob", Value: "sha256:" + p.Payload.SHA256}, {Kind: "oci:tag", Value: base + ":" + p.Tag}}
	if o.Subject != nil {
		refs = append(refs, delivery.Reference{Kind: "oci:subject", Value: base + "@" + o.Subject.Digest})
	}
	return refs
}
func (p Provider) Prepare(d delivery.Description, s delivery.Source, refs []delivery.PayloadRef) (delivery.Preparation, error) {
	o, _, e := ValidateDescription(d)
	if e != nil {
		return delivery.Preparation{}, e
	}
	if len(refs) != 1 || !validPayload(refs[0]) || refs[0].SHA256 != s.OutputSHA256 || !delivery.ValidDigest(s.IndexSHA256) {
		return delivery.Preparation{}, invalid("verified identity SBOM required")
	}
	pub := packageManifest(o, s.IndexSHA256, refs[0])
	o.Publication = &pub
	return delivery.Preparation{Description: description(o, d.DestinationName), ExpectedReferences: expected(o)}, nil
}
func ValidateIntent(i record.Intent) error {
	o, _, e := ValidateDescription(i.Destination)
	if e != nil {
		return e
	}
	if o.Publication == nil {
		return invalid("prepared publication required")
	}
	prepared, e := (Provider{}).Prepare(i.Destination, i.Source, i.Payloads)
	if e != nil {
		return e
	}
	if !delivery.JSONEqual(prepared.Description.Options, i.Destination.Options) || !reflect.DeepEqual(prepared.ExpectedReferences, i.ExpectedReferences) {
		return invalid("intent publication mismatch")
	}
	return nil
}
func ValidateObserverReferences(i record.Intent, refs []delivery.Reference) error {
	if e := ValidateIntent(i); e != nil {
		return e
	}
	if !reflect.DeepEqual(i.ExpectedReferences, refs) {
		return invalid("observer references")
	}
	return nil
}
