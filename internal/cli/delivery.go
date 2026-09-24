package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/runner"
	"github.com/rebaze/rio/internal/manifest"
	"github.com/spf13/cobra"
	"io"
	"os"
)

type deliveryOptions struct {
	index, record, retry        string
	legacyConfig, legacyBinding string
	artifacts, targets          []string
	allowFailed, json           bool
}

// These seams let tests prove that offline commands never resolve secrets/build clients.
var deliveryLookupEnv = os.LookupEnv
var deliveryBuild = func(p delivery.Provider, d delivery.Description) (delivery.Target, error) {
	return p.Build(d, deliveryLookupEnv)
}

func loadDeliveryConfig(path string) (delivery.Config, error) {
	m, e := manifest.Load(path)
	if e != nil {
		var safe *delivery.Error
		if errors.As(e, &safe) {
			return delivery.Config{}, safe
		}
		return delivery.Config{}, delivery.Fail("invalid_manifest", "rio.yaml could not be loaded or validated")
	}
	return delivery.ParseConfig(m.Delivery, m.Dir, m.SHA256)
}
func batchPreflight(path string, o deliveryOptions) (delivery.Config, delivery.BatchPlan, error) {
	c, e := loadDeliveryConfig(path)
	if e != nil {
		return c, delivery.BatchPlan{}, e
	}
	plan, e := delivery.PlanBatch(c, o.index, delivery.PlanOptions{Artifacts: o.artifacts, Targets: o.targets, AllowFailedGate: o.allowFailed}, providers(c.Directory))
	return c, plan, e
}
func deliveryFinish(r runner.Result, e error, o deliveryOptions, global *globalOptions, stdout, stderr io.Writer) error {
	if e != nil && r.Error == nil {
		r, e = runner.Failure(r, e, runner.PreflightCode(e))
	}
	if o.json {
		if err := json.NewEncoder(stdout).Encode(r); err != nil {
			return internalErrorf("writing delivery result")
		}
	} else if !global.quiet {
		word := r.Outcome
		if word == "not-observed" {
			word = "no processing observed"
		}
		fmt.Fprintf(stderr, "%s: %s", r.Operation, word)
		if r.AttemptID != "" {
			fmt.Fprintf(stderr, " (attempt %s)", r.AttemptID)
		}
		fmt.Fprintln(stderr)
		if r.Source != nil {
			fmt.Fprintf(stderr, "artifact=%s gate=%s schemaValidated=%t allowFailedGate=%t sha256=%s\n", r.Source.ArtifactID, r.Source.Gate, r.Source.SchemaValidated, r.Source.AllowFailedGate, r.Source.OutputSHA256)
		}
		if r.Destination != nil {
			fmt.Fprintf(stderr, "destination=%s type=%s target=%s capabilities=%v credentialRefs=%v\n", r.Destination.DestinationName, r.Destination.Type, r.Destination.Identity, r.Destination.Capabilities, r.Destination.CredentialRefs)
		}
		if r.Acknowledgment != "" {
			fmt.Fprintf(stderr, "acknowledgment: %s\n", r.Acknowledgment)
		}
		if r.Activity != "" {
			activity := r.Activity
			if activity == "not-observed" {
				activity = "no processing observed"
			}
			fmt.Fprintf(stderr, "activity: %s\n", activity)
		}
		if r.Verification != "" {
			fmt.Fprintf(stderr, "verification: %s\n", r.Verification)
		}
		for _, ref := range r.ExpectedReferences {
			fmt.Fprintf(stderr, "expected %s: %s\n", ref.Kind, ref.Value)
		}
		if r.Destination != nil {
			if entry, err := adapter(r.Destination.Type); err == nil && entry.HumanObservation != nil {
				for i := len(r.Observations) - 1; i >= 0; i-- {
					if r.Observations[i].Kind == "content" || i == len(r.Observations)-1 {
						fmt.Fprintln(stderr, entry.HumanObservation(r.Observations[i]))
						break
					}
				}
			}
		}
		if r.Journal != nil && len(r.Journal.OrphanTemps) > 0 {
			fmt.Fprintf(stderr, "orphan temporary files ignored: %d\n", len(r.Journal.OrphanTemps))
		}
		if r.RequestMayHaveOccurred && r.ExitCode == 3 {
			fmt.Fprintln(stderr, "A request may already have occurred; remote evidence was not durably recorded. Do not automatically resubmit.")
		}
	}
	if r.ExitCode != 0 {
		if e == nil {
			e = delivery.Fail("delivery_failed", "operation failed")
		}
		return &exitError{code: r.ExitCode, err: e}
	}
	return nil
}
func deliveryFlags(cmd *cobra.Command, o *deliveryOptions, selected, recordFlag bool) {
	f := cmd.Flags()
	f.BoolVar(&o.json, "json", false, "print one versioned result, including handled failures")
	if selected {
		f.StringVar(&o.index, "index", "target/rio/index.json", "normalization index, relative to cwd")
		f.StringArrayVar(&o.targets, "target", nil, "target ID filter (repeatable; default all)")
		f.StringArrayVar(&o.artifacts, "artifact", nil, "indexed artifact ID filter (repeatable; default all)")
		f.BoolVar(&o.allowFailed, "allow-failed-gate", false, "explicitly permit recorded failed gates; digest checks still apply")
	}
	if recordFlag {
		f.StringVar(&o.record, "record", "", "delivery journal directory")
		if !selected {
			cmd.MarkFlagRequired("record")
		}
	}
	// Parse retired flags only to issue an actionable migration refusal, never as a loader.
	f.StringVar(&o.legacyConfig, "config", "", "removed: put targets in rio.yaml and use --manifest")
	f.MarkHidden("config")
	f.StringVar(&o.legacyBinding, "delivery", "", "removed: use --target")
	f.MarkHidden("delivery")
}
func rejectDeliveryInherited(cmd *cobra.Command) error {
	if cmd.Flags().Changed("config") || cmd.Flags().Changed("delivery") {
		return delivery.Fail("removed_flag", "put delivery.targets in rio.yaml; use --manifest and --target")
	}
	if cmd.Flags().Changed("out") {
		return delivery.Fail("invalid_flag", "delivery does not accept --out; use --index")
	}
	if cmd.Name() == "inspect" && cmd.Flags().Changed("manifest") {
		return delivery.Fail("invalid_flag", "inspect reads only --record; --manifest is irrelevant")
	}
	return nil
}
func batchFinish(r runner.BatchResult, e error, o deliveryOptions, g *globalOptions, stdout, stderr io.Writer) error {
	if e != nil && r.Error == nil {
		r, e = runner.BatchFailure(r, e, runner.PreflightCode(e))
	}
	if o.json {
		if err := json.NewEncoder(stdout).Encode(r); err != nil {
			return internalErrorf("writing delivery batch result")
		}
	}
	if !o.json && !g.quiet {
		fmt.Fprintf(stderr, "%s: %s\n", r.Operation, r.Outcome)
		for _, item := range r.Items {
			fmt.Fprintf(stderr, "artifact=%s target=%s state=%s record=%s", item.ArtifactID, item.Target, item.State, item.Record)
			if item.Destination != nil {
				label := "identity"
				if entry, e := adapter(item.Destination.Type); e == nil && entry.HumanIdentityLabel != "" {
					label = entry.HumanIdentityLabel
				}
				fmt.Fprintf(stderr, " %s=%s capabilities=%v", label, item.Destination.Identity, item.Destination.Capabilities)
				if entry, e := adapter(item.Destination.Type); e == nil && entry.HumanDescription != nil {
					fmt.Fprint(stderr, entry.HumanDescription(*item.Destination))
				}
			}
			if item.Source != nil {
				fmt.Fprintf(stderr, " gate=%s schemaValidated=%t allowFailedGate=%t sha256=%s", item.Source.Gate, item.Source.SchemaValidated, item.Source.AllowFailedGate, item.Source.OutputSHA256)
			}
			fmt.Fprintln(stderr)
			for _, ref := range item.ExpectedReferences {
				fmt.Fprintf(stderr, "expected %s: %s\n", ref.Kind, ref.Value)
			}
			if item.Result != nil {
				fmt.Fprintf(stderr, "acknowledgment: %s\n", item.Result.Acknowledgment)
				if item.Result.Verification != "" {
					fmt.Fprintf(stderr, "verification: %s\n", item.Result.Verification)
				}
			}
		}
		for _, rule := range r.UnusedRules {
			fmt.Fprintf(stderr, "unused %s rule: target=%s artifact=%s\n", rule.Rule, rule.Target, rule.ArtifactID)
		}
	}
	if r.ExitCode != 0 {
		if e == nil {
			e = delivery.Fail("delivery_failed", "operation failed")
		}
		return &exitError{code: r.ExitCode, err: e}
	}
	return nil
}
func newDeliveryCommand(g *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "delivery", Short: "Preview, inspect and reconcile delivery evidence", Args: cobra.NoArgs}
	cmd.AddCommand(newDeliveryPlanCommand(g, stdout, stderr), newDeliveryInspectCommand(g, stdout, stderr), newDeliveryReconcileCommand(g, stdout, stderr))
	return cmd
}
