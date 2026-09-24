package cli

import (
	"encoding/json"
	"fmt"
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/dtrack"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/delivery/runner"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"io"
	"os"
)

type deliveryOptions struct {
	index, config, binding, record, retry string
	allowFailed, json                     bool
}

// These seams let tests prove that offline commands never resolve secrets/build clients.
var deliveryLookupEnv = os.LookupEnv
var deliveryBuild = func(p delivery.Provider, d delivery.Description) (delivery.Target, error) {
	return p.Build(d, deliveryLookupEnv)
}

func providers(dir string) map[string]delivery.Provider {
	return map[string]delivery.Provider{"dependency-track": dtrack.Provider{Directory: dir}}
}
func describeConfig(path, binding string, subject delivery.Subject) (delivery.Config, delivery.Binding, delivery.Description, delivery.Provider, error) {
	c, e := delivery.LoadConfig(path)
	if e != nil {
		return c, delivery.Binding{}, delivery.Description{}, nil, e
	}
	return describeLoaded(c, binding, subject)
}
func describeLoaded(c delivery.Config, binding string, subject delivery.Subject) (delivery.Config, delivery.Binding, delivery.Description, delivery.Provider, error) {
	var e error
	registry := providers(c.Directory)
	// Validate even unused destinations/bindings, without secrets, CA reads or network.
	for _, dest := range c.Destinations {
		p, ok := registry[dest.Type]
		if !ok {
			return c, delivery.Binding{}, delivery.Description{}, nil, delivery.Fail("unsupported_adapter", "supported types: dependency-track")
		}
		var n yaml.Node
		n.Encode(map[string]any{"project": map[string]any{"name": "validation", "version": "validation"}})
		if _, e = p.Describe(dest.Options, n, delivery.Subject{}); e != nil {
			return c, delivery.Binding{}, delivery.Description{}, nil, e
		}
	}
	for _, b := range c.Deliveries {
		dest := c.Destinations[b.Destination]
		if _, e = registry[dest.Type].Describe(dest.Options, b.Options, delivery.Subject{Name: "validation", Version: "validation"}); e != nil {
			return c, b, delivery.Description{}, nil, e
		}
	}
	b, ok := c.Deliveries[binding]
	if !ok {
		return c, b, delivery.Description{}, nil, delivery.Fail("binding_missing", "selected delivery")
	}
	dest := c.Destinations[b.Destination]
	p := registry[dest.Type]
	d, e := p.Describe(dest.Options, b.Options, subject)
	d.DestinationName = b.Destination
	return c, b, d, p, e
}
func preflight(o deliveryOptions) (delivery.Config, delivery.Verified, delivery.Description, delivery.Provider, error) {
	c, e := delivery.LoadConfig(o.config)
	if e != nil {
		return c, delivery.Verified{}, delivery.Description{}, nil, e
	}
	return preflightLoaded(c, o)
}
func preflightLoaded(c delivery.Config, o deliveryOptions) (delivery.Config, delivery.Verified, delivery.Description, delivery.Provider, error) {
	b, ok := c.Deliveries[o.binding]
	if !ok {
		return c, delivery.Verified{}, delivery.Description{}, nil, delivery.Fail("binding_missing", "selected delivery")
	}
	v, e := delivery.Verify(o.index, b.Artifact, o.allowFailed)
	if e != nil {
		return c, v, delivery.Description{}, nil, e
	}
	c, _, d, p, e := describeLoaded(c, o.binding, v.Subject())
	return c, v, d, p, e
}
func validateSnapshot(s record.Snapshot) error {
	if _, _, e := dtrack.ValidateDescription(s.Intent.Destination); e != nil {
		return e
	}
	for _, event := range s.Events {
		if event.Kind == "submission" {
			var sub delivery.Submission
			if e := delivery.DecodeJSON(event.Data, &sub, true); e != nil {
				return e
			}
			if e := dtrack.ValidateSubmission(sub); e != nil {
				return e
			}
		}
	}
	return dtrack.ValidateEvidence(s.References, s.Observations)
}
func samePolicy(a, b delivery.Description, reconcile bool) bool {
	ao, ai, e := dtrack.ValidateDescription(a)
	if e != nil {
		return false
	}
	bo, bi, e := dtrack.ValidateDescription(b)
	if e != nil {
		return false
	}
	ab, _ := json.Marshal(ai)
	bb, _ := json.Marshal(bi)
	if string(ab) != string(bb) || a.Type != b.Type || ao.Project != bo.Project {
		return false
	}
	if (ao.AutoCreate == nil) != (bo.AutoCreate == nil) {
		return false
	}
	if ao.AutoCreate != nil && *ao.AutoCreate != *bo.AutoCreate {
		return false
	}
	if reconcile && !ao.AllowHTTP && bo.AllowHTTP {
		return false
	}
	return true
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
		f.StringVar(&o.index, "index", "target/rio/index.json", "normalization index")
		f.StringVar(&o.config, "config", "delivery.yaml", "delivery configuration")
		f.StringVar(&o.binding, "delivery", "", "selected delivery binding")
		cmd.MarkFlagRequired("delivery")
		f.BoolVar(&o.allowFailed, "allow-failed-gate", false, "explicitly permit a recorded failed gate; digest checks still apply")
	}
	if recordFlag {
		f.StringVar(&o.record, "record", "", "delivery journal directory")
		cmd.MarkFlagRequired("record")
	}
}
func rejectDeliveryInherited(cmd *cobra.Command) error {
	for _, f := range []string{"manifest", "out"} {
		if cmd.Flags().Changed(f) {
			return delivery.Fail("invalid_flag", "delivery commands do not accept --"+f)
		}
	}
	return nil
}
func newDeliveryCommand(g *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "delivery", Short: "Preview, inspect and reconcile delivery evidence", Args: cobra.NoArgs}
	cmd.AddCommand(newDeliveryPlanCommand(g, stdout, stderr), newDeliveryInspectCommand(g, stdout, stderr), newDeliveryReconcileCommand(g, stdout, stderr))
	return cmd
}
