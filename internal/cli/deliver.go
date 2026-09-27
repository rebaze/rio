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
	var evidencePath, receiptPath string
	cmd := &cobra.Command{Use: "deliver", Short: "Deliver all indexed SBOMs to configured targets; accepted does not mean ingested", Args: cobra.NoArgs}
	deliveryFlags(cmd, &o, true, true)
	cmd.Flags().StringVar(&o.retry, "retry-of", "", "prior journal; authorize possible duplicate with an explicit fresh --record")
	cmd.Flags().StringVar(&evidencePath, "evidence", "", "publish a new portable v2 record and immutable batch recovery sources")
	cmd.Flags().StringVar(&receiptPath, "receipt", "", "new compact receipt path; existing files are refused")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if cmd.Flags().Changed("evidence") {
			c := &batchCapture{Output: evidencePath, AutoCollect: true}
			if evidencePath == "" {
				e := delivery.Fail("invalid_flag", "--evidence requires a new output path")
				c.note(e)
				return finishDeliveryEvidence(runner.NewBatch("deliver", delivery.BatchPlan{}), e, c, o, g, stdout, stderr)
			}
			r, e := executeDeliverBatch(cmd, g, o, c)
			return finishDeliveryEvidence(r, e, c, o, g, stdout, stderr)
		}
		if e := rejectDeliveryInherited(cmd); e != nil {
			return batchFinish(runner.NewBatch("deliver", delivery.BatchPlan{}), e, o, g, stdout, stderr)
		}
		_, plan, e := batchPreflight(g.manifest, o)
		if e != nil {
			return batchFinish(runner.NewBatch("deliver", plan), e, o, g, stdout, stderr)
		}
		inv, e := startDeliveryInvocation(g, o, plan, receiptPath)
		if e != nil {
			return batchFinish(runner.NewBatch("deliver", plan), e, o, g, stdout, stderr)
		}
		o.receipt = inv
		r, e := runDeliverBatch(cmd, g, o)
		inv.doc.Run.Stages["delivery"] = "completed"
		if e != nil {
			inv.doc.Run.Stages["delivery"] = "failed"
			if r.Outcome == "partial" {
				inv.doc.Run.Stages["delivery"] = "partial"
			}
		}
		publication, finalErr := inv.finish(e)
		if finalErr != nil && finalErr != e {
			r, e = runner.BatchFailure(r, finalErr, 3)
		} else {
			e = finalErr
		}
		inv.publication = &publication
		return batchFinish(r, e, o, g, stdout, stderr)
	}
	return cmd
}
func runDeliverBatch(cmd *cobra.Command, g *globalOptions, o deliveryOptions) (runner.BatchResult, error) {
	return executeDeliverBatch(cmd, g, o, nil)
}
func executeDeliverBatch(cmd *cobra.Command, g *globalOptions, o deliveryOptions, capture *batchCapture) (result runner.BatchResult, err error) {
	r := runner.NewBatch("deliver", delivery.BatchPlan{})
	if e := rejectDeliveryInherited(cmd); e != nil && cmd.Name() != "rio" {
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
	if capture != nil {
		defer func() {
			if capture.Reservation != nil {
				if e := capture.Reservation.Close(); e != nil {
					capture.note(e)
					capture.Publication.Output = nil
					result, err = runner.BatchFailure(result, e, 3)
				}
			}
		}()
		if e := capture.prepare(plan, prepared, o.index, paths); e != nil {
			capture.note(e)
			return r, e
		}
	}
	reservations, e := record.ReserveAll(paths)
	if e != nil {
		return r, e
	}
	if capture != nil {
		if e := capture.Reservation.PublishSources(plan.IndexBytes(), capture.Raw); e != nil {
			capture.note(e)
			for _, res := range reservations {
				if closeErr := res.Close(); closeErr != nil {
					e = closeErr
				}
			}
			return runner.BatchFailure(r, e, 3)
		}
	}
	if capture != nil {
		capture.SourcesReady = true
	}
	var hooks []runner.BatchHooks
	if o.receipt != nil {
		if e := o.receipt.prepareDeliveries(plan, prepared); e != nil {
			for _, res := range reservations {
				_ = res.Close()
			}
			return runner.BatchFailure(r, e, 3)
		}
		hooks = append(hooks, o.receipt.hooks())
	}
	result, err = runner.SubmitBatch(cmd.Context(), r, prepared, reservations, hooks...)
	if capture != nil {
		if e := capture.complete(result); e != nil {
			capture.note(e)
		}
		if capture.AutoCollect {
			if e := capture.collect(); e != nil {
				capture.note(e)
			}
		}
		if capture.EvidenceError != nil {
			return runner.BatchFailure(result, capture.EvidenceError, 3)
		}
	}
	return result, err
}
