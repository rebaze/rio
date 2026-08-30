// Command rio normalizes CycloneDX SBOMs so that identity is usable by
// downstream vulnerability tooling.
package main

import (
	"os"

	"github.com/rebaze/rio/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
