package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Injected at build time via ldflags (see Makefile and .goreleaser.yaml).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:          "rio",
	Short:        "rio command line tool",
	SilenceUsage: true,
	RunE:         run,
}

func init() {
	rootCmd.Version = version
	rootCmd.SetVersionTemplate(fmt.Sprintf("rio %s (commit: %s, built: %s)\n", version, commit, date))
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func run(cmd *cobra.Command, args []string) error {
	_, err := fmt.Fprintln(cmd.OutOrStdout(), "hello from rio")
	return err
}
