package cli

import (
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/delivery/runner"
	"github.com/spf13/cobra"
	"io"
)

func newDeliverCommand(g *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	var o deliveryOptions
	cmd := &cobra.Command{Use: "deliver", Short: "Deliver verified SBOM bytes; accepted does not mean ingested", Long: "Deliver one verified normalization output. --record creates a new journal directory.\nAn accepted receipt acknowledges submission only; it does not prove ingestion.\nUploads are never retried automatically. --retry-of explicitly authorizes a possible duplicate.", Args: cobra.NoArgs}
	deliveryFlags(cmd, &o, true, true)
	cmd.Flags().StringVar(&o.retry, "retry-of", "", "prior journal; authorize possible duplicate with matching source and target")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		r := runner.NewResult("deliver", o.record)
		if e := rejectDeliveryInherited(cmd); e != nil {
			return deliveryFinish(r, e, o, g, stdout, stderr)
		}
		c, v, d, p, e := preflight(o)
		if e != nil {
			return deliveryFinish(r, e, o, g, stdout, stderr)
		}
		source := v.Source()
		r.Source = &source
		r.Destination = &d
		intent := record.Intent{RioVersion: Version(), Binding: o.binding, ConfigSHA256: c.SHA256}
		if o.retry != "" {
			prior, e := record.Read(o.retry)
			if e != nil {
				return deliveryFinish(r, e, o, g, stdout, stderr)
			}
			if e = validateSnapshot(prior); e != nil {
				return deliveryFinish(r, e, o, g, stdout, stderr)
			}
			intent.Retry, e = runner.Retry(prior, v, d, samePolicy(prior.Intent.Destination, d, false), o.retry)
			if e != nil {
				return deliveryFinish(r, e, o, g, stdout, stderr)
			}
		}
		target, e := deliveryBuild(p, d)
		if e != nil {
			return deliveryFinish(r, e, o, g, stdout, stderr)
		}
		r, e = runner.Submit(cmd.Context(), runner.Prepared{Verified: v, Description: d, Intent: intent, Target: target}, o.record)
		return deliveryFinish(r, e, o, g, stdout, stderr)
	}
	return cmd
}
