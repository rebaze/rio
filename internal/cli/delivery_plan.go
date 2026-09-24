package cli

import (
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/runner"
	"github.com/spf13/cobra"
	"io"
)

func newDeliveryPlanCommand(g *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	var o deliveryOptions
	cmd := &cobra.Command{Use: "plan", Short: "Verify and preview indexed artifact-target pairs offline", Args: cobra.NoArgs}
	deliveryFlags(cmd, &o, true, false)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		r := runner.NewBatch("plan", delivery.BatchPlan{})
		if e := rejectDeliveryInherited(cmd); e != nil {
			return batchFinish(r, e, o, g, stdout, stderr)
		}
		_, plan, e := batchPreflight(g.manifest, o)
		r = runner.NewBatch("plan", plan)
		if e == nil {
			r.Outcome = "ready"
		} else {
			for i := range r.Items {
				r.Items[i].State = "unattempted"
			}
		}
		return batchFinish(r, e, o, g, stdout, stderr)
	}
	return cmd
}
