package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/evidence"
	"github.com/spf13/cobra"
)

var recordPublish = evidence.Publish

type recordCounts struct {
	Artifacts  int `json:"artifacts"`
	Deliveries int `json:"deliveries"`
}
type recordResult struct {
	SchemaVersion  int                `json:"schemaVersion"`
	Operation      string             `json:"operation"`
	Outcome        string             `json:"outcome"`
	Output         *evidence.Output   `json:"output,omitempty"`
	OutputMayExist bool               `json:"outputMayExist"`
	Counts         *recordCounts      `json:"counts,omitempty"`
	Record         *evidence.Document `json:"record,omitempty"`
	Error          *delivery.Error    `json:"error,omitempty"`
}

func recordPolicy(a, b record.Intent) error {
	if !samePolicy(a.Destination, b.Destination, false) {
		return delivery.Fail("retry_mismatch", "retry target policies differ")
	}
	return nil
}
func recordFlags(cmd *cobra.Command) error {
	for _, flag := range []string{"manifest", "out"} {
		if cmd.Flags().Changed(flag) {
			return delivery.Fail("invalid_flag", "record commands do not use --manifest or --out")
		}
	}
	return nil
}
func newRecordCommand(g *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	var indexPath, output string
	var journals []string
	var asJSON bool
	cmd := &cobra.Command{Use: "record", Short: "Collect one offline record of current evidence", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		r := recordResult{SchemaVersion: 1, Operation: "record", Outcome: "error"}
		if e := recordFlags(cmd); e != nil {
			return recordFinish(r, nil, e, asJSON, g, stdout, stderr)
		}
		d, e := evidence.Collect(indexPath, journals, Version(), validateSnapshot, recordPolicy)
		if e != nil {
			return recordFinish(r, nil, e, asJSON, g, stdout, stderr)
		}
		r.Counts = countsFor(d)
		raw, e := evidence.Marshal(d)
		if e != nil {
			return recordFinish(r, &d, e, asJSON, g, stdout, stderr)
		}
		pub, e := recordPublish(output, indexPath, journals, raw, validateSnapshot, recordPolicy)
		r.OutputMayExist = pub.OutputMayExist
		r.Output = pub.Output
		if e == nil {
			r.Outcome = "written"
		}
		return recordFinish(r, &d, e, asJSON, g, stdout, stderr)
	}}
	cmd.Flags().StringVar(&indexPath, "index", "target/rio/index.json", "normalization index file")
	cmd.Flags().StringArrayVar(&journals, "delivery-record", nil, "explicit delivery journal directory (repeatable)")
	cmd.Flags().StringVar(&output, "output", "record.json", "new evidence file; existing parent required")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit one versioned result object")
	cmd.AddCommand(newRecordInspectCommand(g, stdout, stderr))
	return cmd
}
func countsFor(d evidence.Document) *recordCounts {
	idx, e := delivery.ParseIndex(d.Normalization.Index)
	if e != nil {
		return nil
	}
	return &recordCounts{Artifacts: len(idx.Artifacts), Deliveries: len(d.Deliveries)}
}
func recordFinish(r recordResult, d *evidence.Document, e error, asJSON bool, g *globalOptions, stdout, stderr io.Writer) error {
	code := ExitOK
	if e != nil {
		r.Outcome = "error"
		var safe *delivery.Error
		if !errors.As(e, &safe) {
			safe = &delivery.Error{Code: "execution_failed", Message: "record operation failed"}
		}
		r.Error = safe
		code = ExitUsage
		if safe.Code == "persistence_failed" || safe.Code == "execution_failed" {
			code = ExitInternal
		}
		e = safe
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(r); err != nil {
			return internalErrorf("writing record result")
		}
	} else if !g.quiet && e == nil && d != nil {
		fmt.Fprintf(stderr, "%s: %s\n", r.Operation, r.Outcome)
		renderRecord(*d, stderr)
	}
	if e != nil {
		if r.OutputMayExist {
			fmt.Fprintln(stderr, "record output may exist; use a new path after inspecting the previous result")
		}
		return &exitError{code: code, err: e}
	}
	return nil
}
func renderRecord(d evidence.Document, w io.Writer) {
	c := countsFor(d)
	fmt.Fprintf(w, "record consistency: artifacts=%d selected deliveries=%d index sha256=%s\n", c.Artifacts, c.Deliveries, d.Normalization.IndexSHA256)
	idx, _ := delivery.ParseIndex(d.Normalization.Index)
	for _, a := range idx.Artifacts {
		fmt.Fprintf(w, "artifact=%s gate=%s schemaValidated=%t\n", a.ID, a.Gate, a.SchemaValidated)
		if a.Context != nil {
			b, _ := json.Marshal(a.Context)
			fmt.Fprintf(w, "artifact=%s supplied context=%s\n", a.ID, b)
		}
	}
	for _, x := range d.Deliveries {
		fmt.Fprintf(w, "attempt=%s artifact=%s destination=%s target=%s acknowledgment=%s\n", x.AttemptID, x.ArtifactID, x.Intent.Destination.DestinationName, x.Intent.Destination.Identity, x.Summary.Acknowledgment)
		if entry, e := adapter(x.Intent.Destination.Type); e == nil && entry.HumanTransportPolicy != nil {
			if policy := entry.HumanTransportPolicy(x.Intent.Destination); policy != "" {
				fmt.Fprintln(w, strings.TrimSpace(policy))
			}
			if o := x.Summary.LastObservation; o != nil && entry.HumanObservation != nil {
				if facts := entry.HumanObservation(o.Observation); facts != "" {
					fmt.Fprintln(w, facts)
				}
			}
		}
		if o := x.Summary.LatestActivity; o != nil {
			fmt.Fprintf(w, "latest activity=%s sequence=%d observedAt=%s\n", o.Observation.Value, o.Sequence, o.ObservedAt)
		}
		if o := x.Summary.LatestVerification; o != nil {
			fmt.Fprintf(w, "latest verification=%s sequence=%d observedAt=%s\n", o.Observation.Value, o.Sequence, o.ObservedAt)
			if entry, e := adapter(x.Intent.Destination.Type); e == nil && entry.HumanObservation != nil {
				fmt.Fprintln(w, entry.HumanObservation(o.Observation))
			}
		}
		for _, ref := range x.Intent.ExpectedReferences {
			fmt.Fprintf(w, "expected %s: %s\n", ref.Kind, ref.Value)
		}
		if o := x.Summary.LastObservation; o != nil && o.Observation.Kind == "unavailable" {
			fmt.Fprintf(w, "last observation=unavailable sequence=%d observedAt=%s\n", o.Sequence, o.ObservedAt)
		}
	}
	fmt.Fprintf(w, "artifacts without selected deliveries=%v; missing selected retry ancestry=%v\n", d.Coverage.ArtifactIDsWithoutSelectedDeliveries, d.Coverage.RetryAttemptIDsNotIncluded)
	fmt.Fprintln(w, "SBOM bytes: not checked or included; normalization inputs/statements/signatures: not included; worker identity: not recorded; authenticated producer identity: not established")
	if c.Deliveries == 0 {
		fmt.Fprintln(w, "No delivery evidence selected; this does not establish that no delivery occurred.")
	}
	for _, n := range d.Coverage.CollectionNotes {
		fmt.Fprintf(w, "collector assertion: attempt=%s orphan temporary files=%d (historical presence not independently checked)\n", n.AttemptID, n.Count)
	}
}
