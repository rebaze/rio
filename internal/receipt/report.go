package receipt

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"

	"github.com/rebaze/rio/internal/delivery"
)

//go:embed report.html.tmpl
var reportTemplate string

type reportModel struct {
	Document
	Digest string
	Size   int
}

func displayValue(v any) string {
	if v == nil {
		return "absent"
	}
	if s, ok := v.(string); ok {
		return s
	}
	raw, _ := json.Marshal(v)
	return string(raw)
}
func observed(v *bool) string {
	if v == nil {
		return "not recorded"
	}
	if *v {
		return "observed"
	}
	return "not observed"
}
func HTML(raw []byte) ([]byte, error) {
	d, e := Parse(raw)
	if e != nil {
		return nil, e
	}
	tmpl, e := template.New("receipt").Funcs(template.FuncMap{"value": displayValue, "tls": observed}).Parse(reportTemplate)
	if e != nil {
		return nil, e
	}
	var out bytes.Buffer
	if e = tmpl.Execute(&out, reportModel{d, delivery.Digest(raw), len(raw)}); e != nil {
		return nil, e
	}
	if out.Len() > 32<<20 {
		return nil, invalid("HTML byte limit")
	}
	return out.Bytes(), nil
}
func Text(raw []byte, w io.Writer) error {
	d, e := Parse(raw)
	if e != nil {
		return e
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "Rio %s — %s: %s\nrun %s\n", d.RioVersion, d.Run.Operation, d.Run.Outcome, d.Run.ID)
	for _, a := range d.Artifacts {
		fmt.Fprintf(&b, "\n%s: %s\n", a.ID, a.State)
		if a.Input != nil {
			fmt.Fprintf(&b, "  consumed %s sha256=%s\n", a.Input.Path, a.Input.SHA256)
		}
		if a.Output != nil {
			fmt.Fprintf(&b, "  output sha256=%s bytes=%d\n", a.Output.SHA256, a.Output.Size)
		}
		if a.Changes != nil {
			for _, c := range a.Changes.Metadata {
				fmt.Fprintf(&b, "  %s: %s → %s (%s assertion, %s)\n", c.Field, displayValue(c.Before), displayValue(c.After), c.Assertion, c.Source)
			}
		}
		if a.Checks != nil {
			fmt.Fprintf(&b, "  gate=%s mode=%s schema=%s findings=%d\n", a.Checks.Gate, a.Checks.Mode, a.Checks.Schema, a.Checks.Findings)
		}
	}
	for _, v := range d.Deliveries {
		fmt.Fprintf(&b, "\n%s → %s (%s): %s\n", v.ArtifactID, v.Target, d.Targets[v.Target].URL, v.State)
		fmt.Fprintf(&b, "  project=%s transport=%s TLS=%s verification=%s\n", displayValue(v.Project), v.Transport.Scheme, observed(v.Transport.TLSObserved), v.Transport.CertificateVerification)
		for _, r := range v.Responses {
			fmt.Fprintf(&b, "  %s=%s HTTP=%d code=%s\n", r.Kind, r.Value, r.HTTPStatus, r.Code)
			for _, ref := range r.References {
				fmt.Fprintf(&b, "    %s: %s\n", ref.Kind, ref.Value)
			}
		}
	}
	fmt.Fprintf(&b, "\nValid structure and internal consistency; unsigned recorded assertions/observations.\nHTTP acceptance does not prove ingestion or retained content.\nJSON sha256=%s bytes=%d\n", delivery.Digest(raw), len(raw))
	_, e = w.Write(b.Bytes())
	return e
}

// PublishReport writes a derived view, never an execution receipt or a source.
func PublishReport(path string, html []byte) (Publication, error) {
	if len(html) > 32<<20 {
		return Publication{}, invalid("HTML byte limit")
	}
	return publishNew(path, html)
}
