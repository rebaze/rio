package cli

import (
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/dtrack"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/delivery/runner"
	"github.com/spf13/cobra"
	"io"
	"time"
)

func newDeliveryReconcileCommand(g *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	var o deliveryOptions
	var wait time.Duration
	cmd := &cobra.Command{Use: "reconcile", Short: "Observe saved receipt activity; never resubmit or claim ingestion", Args: cobra.NoArgs}
	deliveryFlags(cmd, &o, false, true)
	cmd.Flags().StringVar(&o.config, "config", "delivery.yaml", "current delivery configuration")
	cmd.Flags().DurationVar(&wait, "wait", 0, "poll every 3 seconds, up to 10m; false means no processing observed")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		r := runner.NewResult("reconcile", o.record)
		finish := func(e error) error { return deliveryFinish(r, e, o, g, stdout, stderr) }
		if e := rejectDeliveryInherited(cmd); e != nil {
			return finish(e)
		}
		if cmd.Flags().Changed("wait") && (wait <= 0 || wait > 10*time.Minute) {
			return finish(delivery.Fail("invalid_wait", "wait must be positive and at most 10m"))
		}
		w, e := record.Open(o.record)
		if e != nil {
			return finish(e)
		}
		defer w.Close()
		s, e := w.Snapshot()
		if e != nil {
			return finish(e)
		}
		if e = validateSnapshot(s); e != nil {
			return finish(e)
		}
		r = runner.FromSnapshot("reconcile", o.record, s)
		if _, e = dtrack.EventToken(s.References); e != nil {
			return finish(e)
		}
		_, id, e := dtrack.ValidateDescription(s.Intent.Destination)
		if e != nil {
			return finish(e)
		}
		c, b, d, p, e := describeConfig(o.config, s.Intent.Binding, delivery.Subject{Name: id.Project.Name, Version: id.Project.Version})
		if e != nil {
			return finish(e)
		}
		if b.Artifact != s.Intent.Source.ArtifactID || !samePolicy(s.Intent.Destination, d, true) {
			return finish(delivery.Fail("destination_drift", "binding artifact, target or policy changed"))
		}
		target, e := deliveryBuild(p, d)
		if e != nil {
			return finish(e)
		}
		observer, ok := target.(delivery.Observer)
		if !ok {
			return finish(delivery.Fail("unsupported_observation", "destination has no observer"))
		}
		r, e = runner.Reconcile(cmd.Context(), w, observer, c.SHA256, wait)
		r.Record = o.record
		if closeErr := w.Close(); closeErr != nil {
			r, e = runner.Failure(r, closeErr, 3)
		}
		return finish(e)
	}
	return cmd
}
