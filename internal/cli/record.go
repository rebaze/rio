package cli

import (
	"github.com/rebaze/rio/internal/delivery"
	"github.com/spf13/cobra"
	"io"
)

func recordFlags(cmd *cobra.Command) error {
	for _, flag := range []string{"manifest", "out"} {
		if cmd.Flags().Changed(flag) {
			return delivery.Fail("invalid_flag", "record commands do not use --manifest or --out")
		}
	}
	return nil
}
func newRecordCommand(g *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "record", Short: "Inspect, report or recover a compact invocation receipt offline", Args: cobra.NoArgs}
	cmd.AddCommand(newRecordInspectCommand(g, stdout, stderr), newRecordReportCommand(g, stdout, stderr), newRecordRecoverCommand(g, stdout, stderr))
	return cmd
}
