package cli

import (
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/delivery/runner"
	"github.com/rebaze/rio/internal/receipt"
	"github.com/spf13/cobra"
	"io"
	"time"
)

func newDeliveryReconcileCommand(g *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	var o deliveryOptions
	var wait time.Duration
	var receiptPath string
	cmd := &cobra.Command{Use: "reconcile", Short: "Observe saved receipt activity; never resubmit or claim ingestion", Args: cobra.NoArgs}
	deliveryFlags(cmd, &o, false, true)
	cmd.Flags().DurationVar(&wait, "wait", 0, "poll every 3 seconds, up to 10m; false means no processing observed")
	cmd.Flags().StringVar(&receiptPath, "receipt", "", "new compact receipt destination")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if e := rejectDeliveryInherited(cmd); e != nil {
			return deliveryFinish(runner.NewResult("reconcile", o.record), e, o, g, stdout, stderr)
		}
		man, config, e := loadDeliveryManifest(g.manifest)
		if e != nil {
			return deliveryFinish(runner.NewResult("reconcile", o.record), e, o, g, stdout, stderr)
		}
		effective := *g
		effective.out = effectiveOutput(cmd, g, man)
		g = &effective
		o.planned = &plannedBatch{config: config}
		if e = receipt.CheckDestination(receiptPath, []string{o.record}); e != nil {
			return deliveryFinish(runner.NewResult("reconcile", o.record), e, o, g, stdout, stderr)
		}
		s, e := receipt.Start(g.out, receiptPath, "reconcile", Version())
		if e != nil {
			return usageErrorf("no receipt created: %v", e)
		}
		if e = receipt.CheckDestination(s.Path, []string{o.record}); e != nil {
			s.Close()
			return deliveryFinish(runner.NewResult("reconcile", o.record), e, o, g, stdout, stderr)
		}
		o.receipt = &invocation{store: s, doc: s.Initial}
		o.receipt.captureOverrides(cmd)
		r, e := runDeliveryReconcile(cmd, o, g.manifest, wait)
		o.receipt.doc.Run.Stages["delivery"] = "completed"
		if e != nil {
			o.receipt.doc.Run.Stages["delivery"] = "failed"
		}
		pub, finalErr := o.receipt.finish(e)
		o.receipt.publication = &pub
		if finalErr != nil && finalErr != e {
			r, e = runner.Failure(r, finalErr, 3)
		} else {
			e = finalErr
		}
		return deliveryFinish(r, e, o, g, stdout, stderr)
	}
	return cmd
}

func runDeliveryReconcile(cmd *cobra.Command, o deliveryOptions, manifestPath string, wait time.Duration) (r runner.Result, err error) {
	r = runner.NewResult("reconcile", o.record)
	if e := rejectDeliveryInherited(cmd); e != nil {
		return r, e
	}
	if cmd.Flags().Changed("wait") && (wait <= 0 || wait > 10*time.Minute) {
		return r, delivery.Fail("invalid_wait", "wait must be positive and at most 10m")
	}
	w, e := record.Open(o.record)
	if e != nil {
		return r, e
	}
	defer func() {
		if closeErr := w.Close(); closeErr != nil {
			r, err = runner.Failure(r, closeErr, 3)
		}
	}()
	s, e := w.Snapshot()
	if e != nil {
		return r, e
	}
	if e = validateSnapshot(s); e != nil {
		return r, e
	}
	if o.receipt != nil {
		if e = o.receipt.prepareReconcile(s, o.record); e != nil {
			return r, e
		}
	}
	r = runner.FromSnapshot("reconcile", o.record, s)
	entry, e := adapter(s.Intent.Destination.Type)
	if e != nil {
		return r, e
	}
	if cmd.Flags().Changed("wait") && delivery.HasCapability(s.Intent.Destination, "observe-content") {
		return r, delivery.Fail("invalid_wait", "content observations do not poll")
	}
	refs := s.References
	if len(refs) == 0 && delivery.HasCapability(s.Intent.Destination, "observe-content") {
		refs = s.Intent.ExpectedReferences
	}
	if e = entry.ValidateObserverReferences(s.Intent, refs); e != nil {
		return r, e
	}
	subject, e := entry.RecordedSubject(s.Intent.Destination)
	if e != nil {
		return r, e
	}
	var c delivery.Config
	if o.planned != nil {
		c = o.planned.config
	} else {
		c, e = loadDeliveryConfig(manifestPath)
	}
	if e != nil {
		return r, e
	}
	registry := providers(c.Directory)
	if e := delivery.ValidateConfig(c, registry); e != nil {
		return r, e
	}
	d, p, e := delivery.DescribeTarget(c, s.Intent.Destination.DestinationName, s.Intent.Source.ArtifactID, subject, registry)
	if e != nil {
		return r, e
	}
	prepared, e := delivery.Prepare(p, d, s.Intent.Source, s.Intent.Payloads)
	if e != nil {
		return r, e
	}
	d = prepared.Description
	if !equalReferences(prepared.ExpectedReferences, s.Intent.ExpectedReferences) {
		return r, delivery.Fail("destination_drift", "expected references changed")
	}
	if d.DestinationName != s.Intent.Destination.DestinationName || !samePolicy(s.Intent.Destination, d, true) {
		return r, delivery.Fail("destination_drift", "binding artifact, target or policy changed")
	}
	target, e := deliveryBuild(p, d)
	if e != nil {
		return r, e
	}
	observer, ok := target.(delivery.Observer)
	if !ok {
		return r, delivery.Fail("unsupported_observation", "destination has no observer")
	}
	var hooks []runner.ReconcileHooks
	if o.receipt != nil {
		hooks = append(hooks, o.receipt.reconcileHooks())
	}
	r, e = runner.Reconcile(cmd.Context(), w, observer, c.SHA256, wait, hooks...)
	r.Record = o.record
	return r, e
}

func equalReferences(a, b []delivery.Reference) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
