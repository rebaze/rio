package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/receipt"
	"github.com/spf13/cobra"
)

type compactRecordResult struct {
	SchemaVersion int                  `json:"schemaVersion"`
	Operation     string               `json:"operation"`
	Outcome       string               `json:"outcome"`
	InputSHA256   string               `json:"inputSHA256,omitempty"`
	Output        *receipt.Publication `json:"output,omitempty"`
	Record        *receipt.Document    `json:"record,omitempty"`
	Error         *delivery.Error      `json:"error,omitempty"`
}

func compactRecordFinish(result compactRecordResult, e error, asJSON bool, stdout, stderr io.Writer) error {
	if e != nil {
		result.Outcome = "error"
		result.Error = &delivery.Error{Code: "invalid_receipt", Message: e.Error()}
	}
	if asJSON {
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			return internalErrorf("writing record result")
		}
	}
	if e != nil {
		return usageErrorf("%v", e)
	}
	if !asJSON && result.Output != nil {
		fmt.Fprintf(stdout, "%s: %s\n", result.Operation, result.Output.Path)
	}
	return nil
}
func isCompactReceipt(raw []byte) bool {
	var header struct {
		Kind string `json:"kind"`
	}
	return json.Unmarshal(raw, &header) == nil && header.Kind == receipt.Kind
}
func inspectCompactReceipt(raw []byte, asJSON bool, g *globalOptions, stdout, stderr io.Writer) error {
	r := compactRecordResult{SchemaVersion: 1, Operation: "record-inspect", Outcome: "valid", InputSHA256: delivery.Digest(raw)}
	d, e := receipt.Parse(raw)
	if e == nil {
		if asJSON {
			r.Record = &d
		} else if !g.quiet {
			e = receipt.Text(raw, stdout)
		}
	}
	return compactRecordFinish(r, e, asJSON, stdout, stderr)
}
func reportCompactReceipt(raw []byte, output string, asJSON bool, stdout, stderr io.Writer) error {
	r := compactRecordResult{SchemaVersion: 1, Operation: "record-report", Outcome: "written", InputSHA256: delivery.Digest(raw)}
	html, e := receipt.HTML(raw)
	if e == nil {
		pub, err := receipt.PublishReport(output, html)
		r.Output = &pub
		e = err
	}
	return compactRecordFinish(r, e, asJSON, stdout, stderr)
}
func newRecordRecoverCommand(g *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	var run, output string
	var asJSON bool
	cmd := &cobra.Command{Use: "recover", Short: "Recover a receipt from local committed state; never replay requests", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&run, "run", "", "explicit interrupted run directory")
	cmd.Flags().StringVar(&output, "output", "", "fresh recovered receipt path outside recovery sources")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print a structured recovery result")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		r := compactRecordResult{SchemaVersion: 1, Operation: "record-recover", Outcome: "written"}
		e := recordFlags(cmd)
		if e == nil && (run == "" || output == "") {
			e = fmt.Errorf("recover requires --run and --output")
		}
		if e == nil {
			e = protectRecoverySources(run, output)
		}
		if e == nil {
			d, err := recoverInvocation(run)
			e = err
			if e == nil {
				pub, err := receipt.PublishRecovered(output, d)
				r.Output = &pub
				e = err
			}
		}
		return compactRecordFinish(r, e, asJSON, stdout, stderr)
	}
	return cmd
}
func protectRecoverySources(run, output string) error {
	canonical := func(path string) (string, error) {
		abs, e := filepath.Abs(path)
		if e != nil {
			return "", e
		}
		parent, e := filepath.EvalSymlinks(filepath.Dir(abs))
		if e != nil {
			return "", e
		}
		return filepath.Join(parent, filepath.Base(abs)), nil
	}
	dest, e := canonical(output)
	if e != nil {
		return e
	}
	sources := []string{run}
	raw, e := delivery.ReadBounded(filepath.Join(run, ".internal", "attempts.json"), receipt.MaxBytes)
	if e == nil {
		var attempts []recoveryAttempt
		if delivery.DecodeJSON(raw, &attempts, true) == nil {
			for _, a := range attempts {
				sources = append(sources, a.Journal)
			}
		} else {
			var one recoveryReconcile
			if delivery.DecodeJSON(raw, &one, true) != nil {
				return delivery.Fail("invalid_recovery", "attempt mapping")
			}
			sources = append(sources, one.Journal)
		}
	}
	for _, source := range sources {
		src, e := canonical(source)
		if e != nil {
			continue
		}
		for _, namespace := range []string{src, src + ".lock"} {
			rel, e := filepath.Rel(namespace, dest)
			if e == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return fmt.Errorf("recovery output overlaps source namespace; choose a new path outside the run and journals")
			}
		}
	}
	return nil
}
