package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/evidence"
	evidencereport "github.com/rebaze/rio/internal/evidence/report"
	"github.com/spf13/cobra"
)

type reportResult struct {
	SchemaVersion  int              `json:"schemaVersion"`
	Operation      string           `json:"operation"`
	Outcome        string           `json:"outcome"`
	InputSHA256    string           `json:"inputSHA256,omitempty"`
	Output         *evidence.Output `json:"output,omitempty"`
	OutputMayExist bool             `json:"outputMayExist"`
	Error          *delivery.Error  `json:"error,omitempty"`
}

func newRecordReportCommand(g *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	var file, output string
	var asJSON bool
	cmd := &cobra.Command{Use: "report", Short: "Render a validated record as self-contained offline HTML", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&file, "file", "", "portable JSON record (required)")
	cmd.Flags().StringVar(&output, "output", "", "new HTML output file (required)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit one versioned result")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if recordFlags(cmd) == nil && file != "" && output != "" {
			raw, e := delivery.ReadBounded(file, evidence.FileLimit)
			if e == nil && isCompactReceipt(raw) {
				return reportCompactReceipt(raw, output, asJSON, stdout, stderr)
			}
		}
		result := reportResult{SchemaVersion: 1, Operation: "record-report", Outcome: "error"}
		var err error
		run := func() error {
			if e := recordFlags(cmd); e != nil {
				return e
			}
			if file == "" || output == "" {
				return delivery.Fail("invalid_flag", "report requires --file and --output")
			}
			raw, e := delivery.ReadBounded(file, evidence.FileLimit)
			if e != nil {
				return e
			}
			model, e := evidencereport.Load(raw, validateSnapshot, recordPolicy)
			if e != nil {
				return e
			}
			result.InputSHA256 = model.RecordSHA256
			html, e := evidencereport.HTML(model)
			if e != nil {
				return e
			}
			publication, e := evidencereport.Publish(output, file, html)
			result.OutputMayExist = publication.OutputMayExist
			result.Output = publication.Output
			if e == nil {
				result.Outcome = "written"
			}
			return e
		}
		err = run()
		code := ExitOK
		if err != nil {
			var safe *delivery.Error
			if !errors.As(err, &safe) {
				safe = &delivery.Error{Code: "execution_failed", Message: "report operation failed"}
			}
			result.Error = safe
			err = safe
			code = ExitUsage
			if safe.Code == "persistence_failed" || safe.Code == "execution_failed" {
				code = ExitInternal
			}
		}
		if asJSON {
			if e := json.NewEncoder(stdout).Encode(result); e != nil {
				return internalErrorf("writing report result")
			}
		} else if !g.quiet && err == nil {
			fmt.Fprintf(stderr, "record report: %s\ninput JSON sha256=%s\n", result.Output.Path, result.InputSHA256)
		}
		if err != nil {
			return &exitError{code: code, err: err}
		}
		return nil
	}
	return cmd
}
