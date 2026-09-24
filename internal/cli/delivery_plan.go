package cli

import (
	"github.com/rebaze/rio/internal/delivery/runner"
	"github.com/spf13/cobra"
	"io"
)

func newDeliveryPlanCommand(g *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	var o deliveryOptions
	cmd := &cobra.Command{Use: "plan", Short: "Verify and preview one delivery offline", Args: cobra.NoArgs}
	deliveryFlags(cmd, &o, true, false)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		r := runner.NewResult("plan", "")
		if e := rejectDeliveryInherited(cmd); e != nil {
			return deliveryFinish(r, e, o, g, stdout, stderr)
		}
		_, v, d, _, e := preflight(o)
		if e == nil {
			s := v.Source()
			r.Source = &s
			r.Destination = &d
			r.Outcome = "ready"
		}
		return deliveryFinish(r, e, o, g, stdout, stderr)
	}
	return cmd
}
