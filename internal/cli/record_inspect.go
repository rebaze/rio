package cli

import (
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/receipt"
	"github.com/spf13/cobra"
	"io"
)

func newRecordInspectCommand(g *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	var file string
	var asJSON bool
	cmd := &cobra.Command{Use: "inspect", Short: "Validate unsigned receipt structure and internal consistency offline", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&file, "file", "", "compact run receipt (required)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print a structured result including the validated receipt")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		e := recordFlags(cmd)
		if e == nil && file == "" {
			e = delivery.Fail("invalid_flag", "inspect requires --file")
		}
		var raw []byte
		if e == nil {
			raw, e = delivery.ReadBounded(file, receipt.MaxBytes)
		}
		if e != nil {
			return compactRecordFinish(compactRecordResult{SchemaVersion: 1, Operation: "record-inspect"}, e, asJSON, stdout, stderr)
		}
		return inspectCompactReceipt(raw, asJSON, g, stdout, stderr)
	}
	return cmd
}
