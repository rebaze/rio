package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/evidence"
	evidencereport "github.com/rebaze/rio/internal/evidence/report"
	"github.com/spf13/cobra"
)

var recordPublish = evidence.Publish
var recordPublishV2 = evidence.PublishV2

type recordCounts struct {
	Artifacts  int `json:"artifacts"`
	Deliveries int `json:"deliveries"`
}
type recordResult struct {
	raw            []byte
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
	var journals, batches []string
	var schemaVersion int
	var asJSON bool
	cmd := &cobra.Command{Use: "record", Short: "Collect one offline record of current evidence", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		r := recordResult{SchemaVersion: 1, Operation: "record", Outcome: "error"}
		if e := recordFlags(cmd); e != nil {
			return recordFinish(r, nil, e, asJSON, g, stdout, stderr)
		}
		if schemaVersion != 1 && schemaVersion != 2 {
			return recordFinish(r, nil, delivery.Fail("unsupported_version", "record schema version must be 1 or 2"), asJSON, g, stdout, stderr)
		}
		if len(batches) > 0 && schemaVersion != 2 {
			return recordFinish(r, nil, delivery.Fail("invalid_flag", "--batch requires --schema-version 2"), asJSON, g, stdout, stderr)
		}
		var d evidence.Document
		var e error
		if schemaVersion == 2 {
			sourceIndex := indexPath
			if len(batches) > 0 && !cmd.Flags().Changed("index") {
				sourceIndex = ""
			}
			d, e = evidence.CollectV2(sourceIndex, batches, journals, Version(), validateSnapshot, recordPolicy)
		} else {
			d, e = evidence.Collect(indexPath, journals, Version(), validateSnapshot, recordPolicy)
		}
		if e != nil {
			return recordFinish(r, nil, e, asJSON, g, stdout, stderr)
		}
		r.Counts = countsFor(d)
		raw, e := evidence.Marshal(d)
		if e != nil {
			return recordFinish(r, &d, e, asJSON, g, stdout, stderr)
		}
		var pub evidence.Publication
		if schemaVersion == 2 {
			pub, e = recordPublishV2(output, d, raw, validateSnapshot, recordPolicy)
		} else {
			pub, e = recordPublish(output, indexPath, journals, raw, validateSnapshot, recordPolicy)
		}
		r.raw = raw
		r.OutputMayExist = pub.OutputMayExist
		r.Output = pub.Output
		if e == nil {
			r.Outcome = "written"
		}
		return recordFinish(r, &d, e, asJSON, g, stdout, stderr)
	}}
	cmd.Flags().IntVar(&schemaVersion, "schema-version", 1, "record format version (1 or 2)")
	cmd.Flags().StringArrayVar(&batches, "batch", nil, "explicit immutable batch descriptor (repeatable; requires v2)")
	cmd.Flags().StringVar(&indexPath, "index", "target/rio/index.json", "normalization index file")
	cmd.Flags().StringArrayVar(&journals, "delivery-record", nil, "explicit delivery journal directory (repeatable)")
	cmd.Flags().StringVar(&output, "output", "record.json", "new evidence file; existing parent required")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit one versioned result object")
	cmd.AddCommand(newRecordInspectCommand(g, stdout, stderr), newRecordReportCommand(g, stdout, stderr), newRecordRecoverCommand(g, stdout, stderr))
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
		if r.raw != nil {
			if e := renderRecordBytes(r.raw, stderr); e != nil {
				return internalErrorf("rendering record: %w", e)
			}
		} else if e := renderRecord(*d, stderr); e != nil {
			return internalErrorf("rendering record: %w", e)
		}
	}
	if e != nil {
		if r.OutputMayExist {
			fmt.Fprintln(stderr, "record output may exist; use a new path after inspecting the previous result")
		}
		return &exitError{code: code, err: e}
	}
	return nil
}
func renderRecord(d evidence.Document, w io.Writer) error {
	raw, err := evidence.Marshal(d)
	if err != nil {
		return err
	}
	return renderRecordBytes(raw, w)
}
func renderRecordBytes(raw []byte, w io.Writer) error {
	model, err := evidencereport.Load(raw, validateSnapshot, recordPolicy)
	if err != nil {
		return err
	}
	return evidencereport.Text(model, w)
}
