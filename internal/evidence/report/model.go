// Package report renders a validated portable record. It reads no source paths,
// resolves no credentials, and constructs no network clients.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/dtrack"
	"github.com/rebaze/rio/internal/evidence"
	"github.com/rebaze/rio/internal/index"
)

type Model struct {
	RecordSHA256                                      string
	SchemaVersion                                     int
	Collector, Normalizer                             index.Tool
	IndexSHA256, ManifestSHA256                       string
	ScopeStatus, ExpectedScope                        string
	Scope                                             *index.NormalizationScope
	Artifacts                                         []Artifact
	Attempts                                          []Attempt
	Batches                                           []evidence.BatchView
	Sources                                           []Source
	Exceptions                                        []Exception
	Boundaries                                        []string
	Coverage                                          evidence.Coverage
	Changes, ArtifactsWithChangeDetail, SelectedPairs int
	SourceBytes                                       int64
}
type Artifact struct {
	Index                     index.Artifact
	ChangeStatus, CheckStatus string
	Changes, Bookkeeping      []Change
	Checks                    *index.EffectiveChecks
	Unmapped                  []index.Unmapped
	Skipped                   []index.Skipped
	ChangedTop, UnchangedTop  int
	DetailKnown               bool
	Enrichment, Context       string
}
type Change struct {
	Target, Operation, Rule, Before, After   string
	SourceKind, Selector, SHA256, Assertions string
}
type Attempt struct {
	ID, ArtifactID, Target, Type, Identity, Options, Acknowledgment string
	Gate                                                            string
	AllowFailedGate                                                 bool
	Transport, ContentSupport                                       string
	Events                                                          []Event
	Facts                                                           evidence.Delivery
}
type Event struct {
	Sequence         int
	ObservedAt, Kind string
	References       []delivery.Reference
	Observations     []Observation
}
type Observation struct {
	Kind, Value, Origin, Code, Details, TLS string
	HTTPStatus                              int
	References                              []delivery.Reference
}
type Source struct {
	ID, Kind, SHA256 string
	Size             int64
}
type Exception struct{ Scope, Message string }

// Load validates the complete record before constructing the shared view model.
// The hash is over the exact supplied bytes, including whitespace, not a re-encoding.
func Load(raw []byte, validate evidence.Validator, retryPolicy ...evidence.RetryValidator) (Model, error) {
	d, err := evidence.Parse(raw, validate, retryPolicy...)
	if err != nil {
		return Model{}, err
	}
	if (len(d.Deliveries) > 0 || len(d.Batches) > 0) && validate == nil {
		return Model{}, delivery.Fail("invalid_record", "offline adapter validation required for report")
	}
	return build(d, delivery.Digest(raw))
}
func extensionStatus(version int, present bool) string {
	if !present {
		return "not recorded"
	}
	if version != 1 {
		return fmt.Sprintf("unsupported version %d", version)
	}
	return "recorded"
}
func build(d evidence.Document, digest string) (Model, error) {
	idx, err := delivery.ParseIndex(d.Normalization.Index)
	if err != nil {
		return Model{}, err
	}
	m := Model{RecordSHA256: digest, SchemaVersion: d.SchemaVersion, Collector: d.Tool, Normalizer: idx.Tool, IndexSHA256: d.Normalization.IndexSHA256, ManifestSHA256: idx.Manifest.SHA256, Artifacts: []Artifact{}, Attempts: []Attempt{}, Batches: d.Batches, Sources: []Source{}, Exceptions: []Exception{}, Coverage: d.Coverage, ExpectedScope: "not recorded"}
	m.Boundaries = []string{"Keep the original JSON alongside this report for machine inspection.", "Internal consistency does not establish authenticity. This record is unsigned; authenticated producer and worker identity are not established.", "Full SBOMs, normalization input files, raw manifests, complete mapping assets and normalization statements are not included. External SBOM bytes are not rechecked by inspection.", "Receiver acknowledgment, processing activity and content verification are separate facts. Dependency-Track acknowledgment and activity do not prove ingestion or content retention.", "Missing evidence does not establish that no upload occurred. Later observations require a new snapshot; original acknowledgments remain unchanged."}
	add := func(scope, message string) { m.Exceptions = append(m.Exceptions, Exception{scope, message}) }
	if idx.NormalizationScope == nil {
		m.ScopeStatus = "not recorded"
	} else {
		m.ScopeStatus = extensionStatus(idx.NormalizationScope.Version, true)
		if idx.NormalizationScope.Version == 1 {
			m.Scope = idx.NormalizationScope
		}
	}
	if m.Scope == nil {
		add("Normalization scope", m.ScopeStatus+"; the artifact inventory below does not describe unselected modules or original selectors.")
	}
	if d.ExpectedScope == "recorded" {
		m.ExpectedScope = "recorded"
	} else {
		add("Delivery scope", "Expected destinations not recorded; explicit journals do not establish complete delivery coverage.")
	}
	for _, a := range idx.Artifacts {
		v := Artifact{Index: a, ChangeStatus: "not recorded", CheckStatus: "not recorded", Changes: []Change{}, Bookkeeping: []Change{}, Unmapped: []index.Unmapped{}, Skipped: []index.Skipped{}}
		if a.Normalization != nil {
			v.ChangeStatus = extensionStatus(a.Normalization.Version, true)
			if a.Normalization.Version == 1 {
				v.DetailKnown = true
				m.ArtifactsWithChangeDetail++
				m.Changes += len(a.Normalization.Changes)
				changed := map[int]bool{}
				for _, c := range a.Normalization.Changes {
					v.Changes = append(v.Changes, change(c))
					parts := strings.Split(c.Target, "/")
					if len(parts) > 2 && parts[1] == "components" {
						n, e := strconv.Atoi(parts[2])
						if e != nil || n < 0 || n >= a.Components {
							return Model{}, delivery.Fail("invalid_index", "change pointer outside recorded component scope")
						}
						changed[n] = true
					}
				}
				v.ChangedTop = len(changed)
				v.UnchangedTop = a.Components - v.ChangedTop
				for _, c := range a.Normalization.Bookkeeping {
					v.Bookkeeping = append(v.Bookkeeping, change(c))
				}
				v.Unmapped = a.Normalization.Unmapped
				v.Skipped = a.Normalization.Skipped
			}
		}
		if !v.DetailKnown {
			add(a.ID, "Detailed normalization changes "+v.ChangeStatus+"; absence is not zero work.")
		}
		if a.Checks != nil {
			v.CheckStatus = extensionStatus(a.Checks.Version, true)
			if a.Checks.Version == 1 {
				v.Checks = a.Checks
			}
		}
		if v.Checks == nil {
			add(a.ID, "Effective requirements "+v.CheckStatus+"; the historical gate result does not identify which checks ran.")
		}
		if a.Gate == index.GateFail {
			add(a.ID, "Recorded quality gate failed.")
		}
		if !a.SchemaValidated {
			add(a.ID, "Output is not recorded as schema-validated.")
		}
		if len(a.IntegrityFindings) > 0 {
			add(a.ID, fmt.Sprintf("%d dangling dependency reference findings; graph repair was not performed.", len(a.IntegrityFindings)))
		}
		for _, t := range a.Transforms {
			if t.Unmapped > 0 {
				add(a.ID, fmt.Sprintf("%s recorded %d unresolved mappings. An unresolved mapping is not itself a failed field requirement.", t.ID, t.Unmapped))
			}
		}
		if a.Enrichment != nil {
			if a.Enrichment.Version == 1 {
				v.Enrichment = jsonText(a.Enrichment)
			} else {
				v.Enrichment = extensionStatus(a.Enrichment.Version, true) + "; retained source is not interpreted"
				add(a.ID, "Enrichment "+v.Enrichment)
			}
		}
		if a.Context != nil {
			if a.Context.Version == 1 {
				v.Context = jsonText(a.Context)
			} else {
				v.Context = extensionStatus(a.Context.Version, true) + "; retained source is not interpreted"
				add(a.ID, "Context "+v.Context)
			}
		}
		m.Artifacts = append(m.Artifacts, v)
	}
	for _, b := range d.Batches {
		m.SelectedPairs += len(b.Pairs)
		if b.Completion == nil {
			add("Batch "+b.SHA256, "Ordinary-return completion not recorded; retain uncertainty about interrupted work.")
		}
		for _, p := range b.Pairs {
			if p.Evidence == "missing" {
				add(p.ArtifactID+" / "+p.Target, "No captured attempt evidence for "+p.AttemptID+". Runner state: "+p.RunnerState+".")
			}
		}
	}
	for _, x := range d.Deliveries {
		a := Attempt{ID: x.AttemptID, ArtifactID: x.ArtifactID, Target: x.Intent.Destination.DestinationName, Type: x.Intent.Destination.Type, Identity: jsonText(x.Intent.Destination.Identity), Options: jsonText(x.Intent.Destination.Options), Acknowledgment: x.Summary.Acknowledgment, Gate: x.Intent.Source.Gate, AllowFailedGate: x.Intent.Source.AllowFailedGate, Events: []Event{}, Facts: x, ContentSupport: "Only recorded content observations are shown."}
		var options map[string]any
		_ = json.Unmarshal(x.Intent.Destination.Options, &options)
		url, _ := options["url"].(string)
		bypass, _ := options["insecureSkipVerify"].(bool)
		allowHTTP, _ := options["allowHTTP"].(bool)
		plain := strings.HasPrefix(url, "http://") || a.Type == "oci" && allowHTTP
		switch {
		case plain:
			a.Transport = "Plain HTTP configured"
			add(a.ID, "Plain HTTP transport was explicitly configured.")
		case strings.HasPrefix(url, "https://") || a.Type == "oci":
			a.Transport = fmt.Sprintf("HTTPS configured; insecureSkipVerify=%t", bypass)
		default:
			a.Transport = "Transport policy not recorded"
		}
		if bypass {
			add(a.ID, "TLS certificate-chain and hostname verification explicitly disabled.")
		}
		if a.AllowFailedGate {
			add(a.ID, "Failed-gate delivery override was explicitly enabled (allowFailedGate=true); recorded gate="+a.Gate+".")
		}
		if a.Acknowledgment == "unknown" {
			add(a.ID, "Original acknowledgment is unknown; later activity or content observations do not upgrade it.")
		}
		if a.Acknowledgment == "rejected" {
			add(a.ID, "Receiver rejected this attempt.")
		}
		if a.Type == "dependency-track" {
			a.ContentSupport = "Dependency-Track content verification is not supported by this adapter."
		}
		tlsRecorded := false
		for _, event := range x.Events {
			row := Event{Sequence: event.Sequence, ObservedAt: event.ObservedAt, Kind: event.Kind, References: []delivery.Reference{}, Observations: []Observation{}}
			var observations []delivery.Observation
			switch event.Kind {
			case "submission":
				var sub delivery.Submission
				if err = delivery.DecodeJSON(event.Data, &sub, true); err != nil {
					return Model{}, err
				}
				row.References = sub.References
				observations = sub.Observations
			case "reconciliation":
				var rec struct {
					Observation  delivery.Observation `json:"observation"`
					ConfigSHA256 string               `json:"configSHA256"`
				}
				if err = delivery.DecodeJSON(event.Data, &rec, true); err != nil {
					return Model{}, err
				}
				observations = []delivery.Observation{rec.Observation}
			}
			for _, o := range observations {
				obs := Observation{Kind: o.Kind, Value: o.Value, Origin: o.Origin, Code: o.Code, Details: jsonText(o.Details), HTTPStatus: o.HTTPStatus, References: o.References}
				if a.Type == "dependency-track" {
					facts, e := dtrack.ReadTLS(o)
					if e != nil {
						return Model{}, e
					}
					if facts != nil {
						tlsRecorded = true
						obs.TLS = fmt.Sprintf("certificateVerification=%s TLSObserved=%t", facts.CertificateVerification, facts.Observed)
					}
				}
				if o.Kind == "unavailable" {
					add(a.ID, "An observation was unavailable; earlier recorded facts remain in the event history.")
				}
				row.Observations = append(row.Observations, obs)
			}
			a.Events = append(a.Events, row)
		}
		if !plain && !tlsRecorded {
			a.Transport += "; TLS observation facts not recorded"
		}
		m.Attempts = append(m.Attempts, a)
	}
	for _, s := range d.Evidence {
		m.Sources = append(m.Sources, Source{s.ID, s.Kind, s.SHA256, s.Size})
		m.SourceBytes += s.Size
	}
	if len(d.Coverage.RetryAttemptIDsNotIncluded) > 0 {
		add("Retry ancestry", fmt.Sprintf("%d referenced prior attempts were not selected; their history is not reconstructed.", len(d.Coverage.RetryAttemptIDsNotIncluded)))
	}
	return m, nil
}
func change(c index.Change) Change {
	v := Change{Target: c.Target, Operation: c.Operation, Rule: c.Rule, Before: jsonText(c.Before), After: jsonText(c.After)}
	if c.Operation == "add" {
		v.Before = "absent"
	}
	if c.Operation == "remove" {
		v.After = "absent"
	}
	if c.Resolution != nil {
		v.SourceKind = c.Resolution.Kind
		v.Selector = c.Resolution.Selector
		v.SHA256 = c.Resolution.SHA256
		if len(c.Resolution.Metadata) > 0 {
			v.Assertions = jsonText(c.Resolution.Metadata)
		}
	}
	return v
}
func jsonText(v any) string {
	if raw, ok := v.(json.RawMessage); ok && len(raw) == 0 {
		return ""
	}
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(v) != nil {
		return "unavailable"
	}
	return strings.TrimSuffix(b.String(), "\n")
}
