package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/rebaze/rio/internal/discover"
	"github.com/rebaze/rio/internal/manifest"
	"github.com/rebaze/rio/internal/sbom"
	"github.com/spf13/cobra"
)

func newInitCommand(opts *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	var pattern string
	var write bool
	cmd := &cobra.Command{
		Use:     "init",
		Short:   "Preview a starter manifest for an existing CycloneDX SBOM",
		Example: "  rio init\n  rio init --sbom dist/application.cdx.json --write\n  rio plan\n  rio --skip-delivery",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := discover.Resolve(filepath.Dir(opts.manifest), "app", pattern)
			if err != nil {
				return usageErrorf("%v\nRun your SBOM producer first or select its output with --sbom.", err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return usageErrorf("reading %q: %v", path, err)
			}
			if _, err := sbom.Load(data); err != nil {
				return usageErrorf("reading %q: %v", path, err)
			}

			proposal := fmt.Sprintf("version: %d\nartifacts:\n  - id: app\n    sbom: %q\n", manifest.Version, filepath.ToSlash(pattern))
			if !write {
				if _, err := io.WriteString(stdout, proposal); err != nil {
					return internalErrorf("writing preview: %v", err)
				}
				if !opts.quiet {
					fmt.Fprintln(stderr, "To save this proposal, repeat the command with --write.")
				}
				return nil
			}
			if err := saveStarterManifest(opts.manifest, proposal); err != nil {
				if errors.Is(err, os.ErrExist) {
					return usageErrorf("%q already exists; review your existing manifest with rio plan", opts.manifest)
				}
				return usageErrorf("creating %q: %v", opts.manifest, err)
			}
			if !opts.quiet {
				fmt.Fprintf(stderr, "Created %s. Run rio plan, then rio --skip-delivery for your first receipt.\n", opts.manifest)
				if cmd.Flags().Changed("manifest") {
					fmt.Fprintln(stderr, "Pass the same --manifest option to both commands.")
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&pattern, "sbom", "target/bom.json", "SBOM path or single-match glob, relative to the manifest")
	cmd.Flags().BoolVar(&write, "write", false, "create the manifest at --manifest (must be a new file)")
	return cmd
}

// Link a completed sibling file so a concurrent init or existing symlink
// can never be overwritten and readers only see a complete manifest.
func saveStarterManifest(path, proposal string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".rio-init-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = io.WriteString(f, proposal)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Link(f.Name(), path)
}
