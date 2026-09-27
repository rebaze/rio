package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
)

// terminal leaves ordinary names readable but quotes control characters.
func terminal(s string) string {
	for _, r := range s {
		if unicode.IsControl(r) {
			return strconv.Quote(s)
		}
	}
	return s
}
func Text(m Model, w io.Writer) error {
	var err error
	write := func(format string, args ...any) {
		for i, arg := range args {
			switch v := arg.(type) {
			case string:
				args[i] = terminal(v)
			case []string:
				copy := make([]string, len(v))
				for n, s := range v {
					copy[n] = terminal(s)
				}
				args[i] = copy
			}
		}
		if err == nil {
			_, err = fmt.Fprintf(w, format, args...)
		}
	}
	write("record consistency: artifacts=%d selected deliveries=%d index sha256=%s\n", len(m.Artifacts), len(m.Attempts), m.IndexSHA256)
	write("record JSON sha256=%s; format=%d; normalization scope=%s; expected delivery scope=%s\n", m.RecordSHA256, m.SchemaVersion, m.ScopeStatus, m.ExpectedScope)
	if m.Scope != nil {
		write("output spec floor=%s; explicit artifacts=%v\n", m.Scope.SpecVersionFloor, m.Scope.ExplicitArtifacts)
		for _, s := range m.Scope.ArtifactSets {
			write("%s modules=%s exclusions=%v selected artifacts=%v\n", terminal(s.Source), terminal(s.Modules), s.Exclude, s.ArtifactIDs)
		}
	}
	if m.ArtifactsWithChangeDetail > 0 {
		write("work performed: %d recorded changes; supported detail for %d/%d artifacts\n", m.Changes, m.ArtifactsWithChangeDetail, len(m.Artifacts))
	} else {
		write("work performed: detailed changes not recorded in a supported extension\n")
	}
	for _, a := range m.Artifacts {
		x := a.Index
		write("artifact=%s gate=%s schemaValidated=%t spec=%s to %s; top-level components=%d\n", terminal(x.ID), x.Gate, x.SchemaValidated, x.SpecVersion.Input, x.SpecVersion.Output, x.Components)
		write("  changes=%s; effective checks=%s\n", a.ChangeStatus, a.CheckStatus)
		if a.DetailKnown {
			write("  substantive changes affect %d/%d top-level components; unchanged=%d\n", a.ChangedTop, x.Components, a.UnchangedTop)
		}
		for _, c := range a.Changes {
			write("  %s %s rule=%s: %s -> %s\n", c.Operation, terminal(c.Target), terminal(c.Rule), c.Before, c.After)
			if c.SourceKind != "" {
				write("    source=%s selector=%s sha256=%s assertions=%s\n", terminal(c.SourceKind), terminal(c.Selector), c.SHA256, c.Assertions)
			}
		}
		for _, t := range x.Transforms {
			write("  transform=%s applied=%d unmapped=%d skipped=%d (top-level scope; applied/unmapped can overlap)\n", terminal(t.ID), t.Applied, t.Unmapped, t.Skipped)
		}
		for _, u := range a.Unmapped {
			write("  unresolved %s: %s (%s)\n", terminal(u.Target), terminal(u.Reason), terminal(u.PURL))
		}
		for _, s := range a.Skipped {
			write("  skipped=%d rule=%s scope=%s reason=%s\n", s.Count, terminal(s.Rule), terminal(s.Scope), terminal(s.Reason))
		}
		if a.Checks != nil {
			c := a.Checks
			write("  checks mode=%s; component scope=%s; component evaluation=%s; count=%d\n", c.Mode, c.ComponentScope, c.ComponentEvaluation, c.ComponentCount)
			for _, e := range c.Evaluations {
				write("    %s/%s evaluated=%d failed=%d outcome=%s\n", e.Scope, e.Requirement, e.Evaluated, e.Failed, e.Outcome)
			}
			write("  schema=%s; graph check=%s findings=%d\n", c.SchemaValidation, c.GraphCheck, c.GraphFindings)
		}
		if a.Enrichment != "" {
			write("  supplied enrichment=%s\n", a.Enrichment)
		}
		if a.Context != "" {
			write("artifact=%s supplied context=%s\n", terminal(x.ID), a.Context)
		}
	}
	for _, b := range m.Batches {
		write("batch=%s normalization manifest=%s delivery manifest=%s\n", b.SHA256, b.Scope.NormalizationManifestSHA256, b.Scope.DeliveryManifestSHA256)
		for _, p := range b.Pairs {
			write("  expected artifact=%s target=%s attempt=%s evidence=%s acknowledgment=%s runner=%s\n", terminal(p.ArtifactID), terminal(p.Target), p.AttemptID, p.Evidence, p.Acknowledgment, p.RunnerState)
		}
		for _, e := range b.Exclusions {
			write("  excluded=%d reason=%s artifacts=%v targets=%v\n", e.PairCount, e.Reason, e.ArtifactIDs, e.Targets)
		}
	}
	for _, a := range m.Attempts {
		write("attempt=%s artifact=%s destination=%s target=%s acknowledgment=%s\n", a.ID, terminal(a.ArtifactID), terminal(a.Target), a.Identity, a.Acknowledgment)
		write("  %s; %s\n", a.Transport, a.ContentSupport)
		for _, p := range a.Facts.Intent.Payloads {
			write("  payload role=%s bytes=%d sha256=%s transformation=%s\n", terminal(p.Role), p.Size, p.SHA256, terminal(p.Transformation))
		}
		for _, r := range a.Facts.Intent.ExpectedReferences {
			write("  expected %s: %s\n", terminal(r.Kind), terminal(r.Value))
		}
		for _, e := range a.Events {
			write("  event sequence=%d kind=%s observedAt=%s\n", e.Sequence, e.Kind, e.ObservedAt)
			for _, r := range e.References {
				write("    receipt %s: %s\n", terminal(r.Kind), terminal(r.Value))
			}
			for _, o := range e.Observations {
				write("    %s=%s code=%s origin=%s HTTP=%d %s\n", o.Kind, o.Value, o.Code, o.Origin, o.HTTPStatus, o.TLS)
				if o.Details != "" {
					write("    details=%s\n", o.Details)
				}
			}
		}
	}
	if len(m.Attempts) == 0 {
		write("No delivery evidence selected; this does not establish that no delivery occurred.\n")
	}
	for _, e := range m.Exceptions {
		write("exception [%s]: %s\n", terminal(e.Scope), terminal(e.Message))
	}
	write("artifacts without selected deliveries=%v; missing selected retry ancestry=%v\n", m.Coverage.ArtifactIDsWithoutSelectedDeliveries, m.Coverage.RetryAttemptIDsNotIncluded)
	for _, n := range m.Coverage.CollectionNotes {
		write("collector assertion: attempt=%s orphan temporary files=%d (historical presence not independently checked)\n", n.AttemptID, n.Count)
	}
	write("evidence: %d sources, %d raw bytes; normalizer=%s %s; collector=%s %s\n", len(m.Sources), m.SourceBytes, terminal(m.Normalizer.Name), terminal(m.Normalizer.Version), terminal(m.Collector.Name), terminal(m.Collector.Version))
	for _, b := range m.Boundaries {
		write("%s\n", strings.TrimSpace(b))
	}
	return err
}
