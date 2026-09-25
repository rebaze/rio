package cli

import (
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/delivery/runner"
	"github.com/spf13/cobra"
	"io"
	"os"
	"path/filepath"
)

func newDeliverCommand(g *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	var o deliveryOptions
	cmd := &cobra.Command{Use: "deliver", Short: "Deliver all indexed SBOMs to configured targets; accepted does not mean ingested", Args: cobra.NoArgs}
	deliveryFlags(cmd, &o, true, true)
	cmd.Flags().StringVar(&o.retry, "retry-of", "", "prior journal; authorize possible duplicate with an explicit fresh --record")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		r, e := runDeliverBatch(cmd, g, o)
		return batchFinish(r, e, o, g, stdout, stderr)
	}
	return cmd
}
func runDeliverBatch(cmd *cobra.Command, g *globalOptions, o deliveryOptions) (runner.BatchResult, error) {
	r := runner.NewBatch("deliver", delivery.BatchPlan{})
	if e := rejectDeliveryInherited(cmd); e != nil {
		return r, e
	}
	c, plan, e := batchPreflight(g.manifest, o)
	r = runner.NewBatch("deliver", plan)
	if e != nil {
		return r, e
	}
	if o.record != "" && len(plan.Jobs) != 1 || o.retry != "" && (len(plan.Jobs) != 1 || !cmd.Flags().Changed("record") || o.record == "") {
		return r, delivery.Fail("invalid_selection", "--record requires one pair; --retry-of also requires an explicit fresh --record")
	}
	if o.record != "" {
		path, e := filepath.Abs(o.record)
		if e != nil {
			return r, delivery.Fail("invalid_record_path", "record")
		}
		plan.Jobs[0].Record = path
		r.Items[0].Record = path
	}
	prepared := make([]runner.Prepared, 0, len(plan.Jobs))
	paths := make([]string, 0, len(plan.Jobs))
	for i, j := range plan.Jobs {
		intent := record.Intent{RioVersion: Version(), Binding: j.Target, ConfigSHA256: c.SHA256}
		if o.retry != "" {
			prior, e := record.Read(o.retry)
			if e != nil {
				return r, e
			}
			if e := validateSnapshot(prior); e != nil {
				return r, e
			}
			intent.Retry, e = runner.Retry(prior, j.Verified, j.Description, samePolicy(prior.Intent.Destination, j.Description, false), o.retry)
			if e != nil {
				return r, e
			}
		}
		target, e := deliveryBuild(j.Provider, j.Description)
		if e != nil {
			r.Items[i].State = "error"
			if safe, ok := e.(*delivery.Error); ok {
				r.Items[i].Error = safe
			}
			return r, e
		}
		entry, e := adapter(j.Description.Type)
		if e != nil {
			return r, e
		}
		p := runner.Prepared{ExpectedReferences: j.ExpectedReferences, ValidateIntent: entry.ValidateIntent, Verified: j.Verified, Description: j.Description, Intent: intent, Target: target}
		p.Intent, e = runner.PrepareIntent(p)
		if e != nil {
			r.Items[i].State = "error"
			if safe, ok := e.(*delivery.Error); ok {
				r.Items[i].Error = safe
			}
			return r, e
		}
		prepared = append(prepared, p)
		paths = append(paths, j.Record)
	}
	if o.record == "" {
		// The index's existing directory is the parent. Never create unrelated ancestors.
		parent := filepath.Dir(paths[0])
		if e := os.Mkdir(parent, 0700); e != nil && !os.IsExist(e) {
			return r, delivery.Fail("persistence_failed", "create automatic journal parent")
		}
	}
	reservations, e := record.ReserveAll(paths)
	if e != nil {
		return r, e
	}
	return runner.SubmitBatch(cmd.Context(), r, prepared, reservations)
}
