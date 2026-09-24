package cli

import (
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/delivery/runner"
	"github.com/spf13/cobra"
	"io"
)

func newDeliveryInspectCommand(g *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	var o deliveryOptions
	cmd := &cobra.Command{Use: "inspect", Short: "Read a journal offline; unknown is a valid inspect result", Args: cobra.NoArgs}
	deliveryFlags(cmd, &o, false, true)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		r := runner.NewResult("inspect", o.record)
		if e := rejectDeliveryInherited(cmd); e != nil {
			return deliveryFinish(r, e, o, g, stdout, stderr)
		}
		s, e := record.Read(o.record)
		if e == nil {
			e = validateSnapshot(s)
		}
		if e == nil {
			r = runner.FromSnapshot("inspect", o.record, s)
			r.Journal = &s
		}
		return deliveryFinish(r, e, o, g, stdout, stderr)
	}
	return cmd
}
