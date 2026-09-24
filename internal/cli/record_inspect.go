package cli

import (
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/evidence"
	"github.com/spf13/cobra"
	"io"
)

func newRecordInspectCommand(g *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	var file string
	var asJSON bool
	cmd := &cobra.Command{Use: "inspect", Short: "Check a record's embedded evidence and readable claims offline", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		r := recordResult{SchemaVersion: 1, Operation: "record-inspect", Outcome: "error"}
		e := recordFlags(cmd)
		if e == nil && file == "" {
			e = delivery.Fail("invalid_flag", "inspect requires --file")
		}
		if e != nil {
			return recordFinish(r, nil, e, asJSON, g, stdout, stderr)
		}
		raw, e := delivery.ReadBounded(file, evidence.FileLimit)
		if e != nil {
			return recordFinish(r, nil, e, asJSON, g, stdout, stderr)
		}
		d, e := evidence.Parse(raw, validateSnapshot, recordPolicy)
		if e != nil {
			return recordFinish(r, nil, e, asJSON, g, stdout, stderr)
		}
		r.Outcome = "valid"
		r.Counts = countsFor(d)
		if asJSON {
			r.Record = &d
		}
		return recordFinish(r, &d, nil, asJSON, g, stdout, stderr)
	}}
	cmd.Flags().StringVar(&file, "file", "", "consolidated evidence file (required)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit one versioned result including the validated document")
	return cmd
}
