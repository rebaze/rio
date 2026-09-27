package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/batchrecord"
	"github.com/rebaze/rio/internal/delivery/record"
	"github.com/rebaze/rio/internal/delivery/runner"
	"github.com/rebaze/rio/internal/evidence"
)

// batchCapture is the local durable-source lifecycle shared with automatic
// collection. It owns no network operations and never retries a submission.
type batchCapture struct {
	AutoCollect    bool
	SourcesReady   bool
	Publication    evidence.Publication
	EvidenceErrors []*delivery.Error
	Output         string
	Reservation    *batchrecord.Reservation
	Descriptor     batchrecord.Descriptor
	Raw            []byte
	DeliveryResult runner.BatchResult
	EvidenceError  error
}

func (c *batchCapture) prepare(plan delivery.BatchPlan, prepared []runner.Prepared, indexPath string, paths []string) error {
	r, err := batchrecord.Reserve(c.Output, indexPath, paths)
	if err != nil {
		_, presence := os.Lstat(c.Output)
		c.Publication.OutputMayExist = !os.IsNotExist(presence)
		return err
	}
	c.Reservation = r
	intents := make([]record.Intent, len(prepared))
	ids := make([]string, len(prepared))
	for i, p := range prepared {
		intents[i] = p.Intent
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return delivery.Fail("persistence_failed", "allocate batch attempt identity")
		}
		ids[i] = hex.EncodeToString(raw)
		prepared[i].AttemptID = ids[i]
	}
	c.Descriptor, err = batchrecord.New(plan, intents, ids, r.Paths)
	if err != nil {
		return err
	}
	c.Raw, err = batchrecord.MarshalDescriptor(c.Descriptor)
	if err != nil {
		return err
	}
	// Refuse a known-over-budget minimum before sending anything. Submission
	// bytes are unknown until the receiver responds; those can still exceed limits.
	minimum := int64(len(plan.IndexBytes()) + len(c.Raw))
	for i, intent := range intents {
		data, e := json.Marshal(intent)
		if e != nil {
			return delivery.Fail("invalid_record", "prepared intent")
		}
		event := record.Event{SchemaVersion: 1, Sequence: 0, AttemptID: ids[i], ObservedAt: "2000-01-01T00:00:00Z", Kind: "intent", Data: data}
		raw, e := json.MarshalIndent(event, "", "  ")
		if e != nil {
			return e
		}
		minimum += int64(len(raw) + 1)
	}
	if minimum > evidence.SourceLimit {
		return delivery.Fail("size_limit", "known batch evidence exceeds aggregate source limit")
	}
	return nil
}
func (c *batchCapture) complete(r runner.BatchResult) error {
	c.DeliveryResult = r
	completion, err := runner.BatchCompletion(c.Descriptor, c.Raw, r)
	if err != nil {
		return err
	}
	return c.Reservation.PublishCompletion(completion, c.Descriptor, c.Raw)
}

// The final publication shares the reservation acquired before any request.
var publishAutomaticEvidence = func(r *batchrecord.Reservation, raw []byte) (evidence.Publication, error) {
	may, err := r.Publish(r.Paths.Output, raw, evidence.FileLimit, func(raw []byte) error { _, e := evidence.Parse(raw, validateSnapshot, recordPolicy); return e })
	p := evidence.Publication{OutputMayExist: may}
	if err == nil {
		p.Output = &evidence.Output{Path: r.Paths.Output, SHA256: delivery.Digest(raw), Size: int64(len(raw))}
	}
	return p, err
}

func (c *batchCapture) collect() error {
	d, err := evidence.CollectV2("", []string{c.Reservation.Paths.Descriptor}, nil, Version(), validateSnapshot, recordPolicy)
	if err != nil {
		return err
	}
	raw, err := evidence.Marshal(d)
	if err != nil {
		return err
	}
	c.Publication, err = publishAutomaticEvidence(c.Reservation, raw)
	return err
}
func (c *batchCapture) note(err error) {
	if err == nil {
		return
	}
	c.EvidenceError = err
	var safe *delivery.Error
	if !errors.As(err, &safe) {
		safe = &delivery.Error{Code: "execution_failed", Message: "evidence operation failed"}
	}
	c.EvidenceErrors = append(c.EvidenceErrors, safe)
}

type deliveryEvidenceView struct {
	Output            *evidence.Output  `json:"output,omitempty"`
	OutputMayExist    bool              `json:"outputMayExist"`
	BatchPath         string            `json:"batchPath,omitempty"`
	IndexSnapshotPath string            `json:"indexSnapshotPath,omitempty"`
	CompletionPath    string            `json:"completionPath,omitempty"`
	RecoveryCommand   []string          `json:"recoveryCommand"`
	Errors            []*delivery.Error `json:"errors"`
}
type deliveryEvidenceResult struct {
	SchemaVersion          int                  `json:"schemaVersion"`
	Operation              string               `json:"operation"`
	Outcome                string               `json:"outcome"`
	RequestMayHaveOccurred bool                 `json:"requestMayHaveOccurred"`
	Delivery               runner.BatchResult   `json:"delivery"`
	Evidence               deliveryEvidenceView `json:"evidence"`
}

func finishDeliveryEvidence(r runner.BatchResult, err error, c *batchCapture, o deliveryOptions, g *globalOptions, stdout, stderr io.Writer) error {
	if err != nil && r.Error == nil {
		r, err = runner.BatchFailure(r, err, runner.PreflightCode(err))
	}
	original := c.DeliveryResult
	if original.Operation == "" {
		original = r
	}
	view := deliveryEvidenceView{Output: c.Publication.Output, OutputMayExist: c.Publication.OutputMayExist, RecoveryCommand: []string{}, Errors: append([]*delivery.Error{}, c.EvidenceErrors...)}
	if c.SourcesReady {
		p := c.Reservation.Paths
		view.BatchPath = p.Descriptor
		view.IndexSnapshotPath = p.Index
		view.CompletionPath = p.Completion
		view.RecoveryCommand = []string{"rio", "record", "--schema-version", "2", "--batch", p.Descriptor, "--output", p.Output + ".recovered-" + delivery.Digest(c.Raw)[:12] + ".json"}
	}
	outcome := r.Outcome
	if len(view.Errors) > 0 {
		outcome = "error"
	}
	result := deliveryEvidenceResult{SchemaVersion: 3, Operation: "deliver", Outcome: outcome, RequestMayHaveOccurred: r.RequestMayHaveOccurred, Delivery: original, Evidence: view}
	if o.json {
		if e := json.NewEncoder(stdout).Encode(result); e != nil {
			return internalErrorf("writing evidence delivery result")
		}
	} else if !g.quiet {
		display := o
		display.json = false
		_ = batchFinish(original, nil, display, g, stdout, stderr)
		if view.Output != nil {
			fmt.Fprintf(stderr, "record: %s (sha256 %s)\n", view.Output.Path, view.Output.SHA256)
		}
		if view.BatchPath != "" {
			fmt.Fprintf(stderr, "batch evidence: %s\n", view.BatchPath)
		}
		if len(view.Errors) > 0 {
			for _, e := range view.Errors {
				fmt.Fprintf(stderr, "evidence: %s\n", e)
			}
			fmt.Fprintf(stderr, "requestMayHaveOccurred=%t outputMayExist=%t; do not automatically resubmit\n", result.RequestMayHaveOccurred, view.OutputMayExist)
			if len(view.RecoveryCommand) > 0 {
				args := []string{}
				for _, a := range view.RecoveryCommand {
					args = append(args, recoveryQuote(a))
				}
				fmt.Fprintf(stderr, "offline recovery: %s\n", strings.Join(args, " "))
			}
		}
	}
	if r.ExitCode != 0 {
		return &exitError{code: r.ExitCode, err: err}
	}
	return nil
}
func recoveryQuote(s string) string {
	if runtime.GOOS == "windows" {
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
