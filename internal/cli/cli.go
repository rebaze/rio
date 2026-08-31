// Package cli is the cobra command tree. Later commands (rio record, verify,
// sign) register as siblings of normalize and inherit its persistent flags;
// they communicate through index.json on disk, never through each other's
// internals (§9a).
package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// Exit codes (§1).
const (
	ExitOK       = 0 // every artifact processed, no gate failure under --gate fail
	ExitGate     = 1 // at least one artifact failed the gate under --gate fail
	ExitUsage    = 2 // usage or configuration error; nothing was written
	ExitInternal = 3 // internal error
)

// Injected at build time via ldflags (see Makefile and .goreleaser.yaml).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Version reports the build version, which is stamped into index.json and into
// the output document's metadata.
func Version() string { return version }

// exitError carries the exit code a failure maps to.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

// usageErrorf builds an exit 2: a usage or configuration problem that aborts
// the run before anything is written.
func usageErrorf(format string, args ...any) error {
	return &exitError{code: ExitUsage, err: fmt.Errorf(format, args...)}
}

// internalErrorf builds an exit 3.
func internalErrorf(format string, args ...any) error {
	return &exitError{code: ExitInternal, err: fmt.Errorf(format, args...)}
}

// gateFailure is the sentinel for exit 1. Unlike the others it is a result,
// not an error: every output file and the index are written first, because a
// human has to be able to see why the gate failed (§1).
var gateFailure = &exitError{code: ExitGate, err: errors.New("gate failed")}

type globalOptions struct {
	manifest string
	out      string
	quiet    bool
}

func newRootCommand(opts *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:   "rio",
		Short: "Collect, normalize and gate a build's supply chain evidence",
		Long: "rio is the open supply chain governance CLI. It collects the evidence your\n" +
			"build already produces, normalizes it into a shape downstream tools can\n" +
			"resolve, and holds it to the quality you declared in the manifest.\n\n" +
			"One manifest in; one normalized document per artifact plus index.json out.\n" +
			"Every repair and every miss is recorded in the document that carries it.\n\n" +
			"rio makes no network calls.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetVersionTemplate(versionLine())

	// Persistent, so rio record, verify and sign inherit them (§8, §9a).
	flags := root.PersistentFlags()
	flags.StringVar(&opts.manifest, "manifest", "rio.yaml", "path to manifest")
	flags.StringVar(&opts.out, "out", "target/rio", "output directory")
	flags.BoolVar(&opts.quiet, "quiet", false, "suppress per artifact progress on stdout")

	root.AddCommand(newNormalizeCommand(opts, stdout, stderr))
	root.AddCommand(newPlanCommand(opts, stdout))
	root.AddCommand(newVersionCommand(stdout))
	return root
}

func versionLine() string {
	return fmt.Sprintf("rio %s (commit: %s, built: %s)\n", version, commit, date)
}

func newVersionCommand(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the rio version",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			_, err := io.WriteString(stdout, versionLine())
			return err
		},
	}
}

// Main runs the command tree and maps failures onto the exit codes in §1.
func Main(args []string, stdout, stderr io.Writer) int {
	var opts globalOptions
	root := newRootCommand(&opts, stdout, stderr)
	root.SetArgs(args)

	err := root.Execute()
	if err == nil {
		return ExitOK
	}

	var exit *exitError
	if errors.As(err, &exit) {
		if exit.code != ExitGate {
			fmt.Fprintf(stderr, "rio: %v\n", err)
		}
		return exit.code
	}

	// Anything cobra itself rejects (unknown flag, unknown command, bad
	// argument count) is a usage error.
	fmt.Fprintf(stderr, "rio: %v\n", err)
	return ExitUsage
}
