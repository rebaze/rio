package cli

import (
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/receipt"
	"github.com/spf13/cobra"
	"io"
)

func newRecordReportCommand(g *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	var file, output string
	var asJSON bool
	cmd := &cobra.Command{Use: "report", Short: "Render a compact receipt as self-contained offline HTML", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&file, "file", "", "compact run receipt (required)")
	cmd.Flags().StringVar(&output, "output", "", "new HTML file (required)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print a structured report result")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		e := recordFlags(cmd)
		if e == nil && (file == "" || output == "") {
			e = delivery.Fail("invalid_flag", "report requires --file and --output")
		}
		var raw []byte
		if e == nil {
			raw, e = delivery.ReadBounded(file, receipt.MaxBytes)
		}
		if e != nil {
			return compactRecordFinish(compactRecordResult{SchemaVersion: 1, Operation: "record-report"}, e, asJSON, stdout, stderr)
		}
		return reportCompactReceipt(raw, output, asJSON, stdout, stderr)
	}
	return cmd
}
