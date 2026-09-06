//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// #12: a directory rio may not read can hold a second SBOM, and then the
// exactly-one rule passes on a tree rio never fully saw. Both commands resolve
// the glob through the same discover.Resolve, so both have to refuse: plan is
// the machine-readable contract tools/build-p2-table.py consumes, and a plan
// that names one input while a second is hidden is wrong in the same way a
// normalize run is, without even writing a file a human might inspect.
func TestIncompleteSearchExitsTwoInBothCommands(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not deny anything")
	}

	for _, command := range []string{"normalize", "plan"} {
		t.Run(command, func(t *testing.T) {
			manifest := "version: 1\nartifacts:\n  - id: rcp-client\n    sbom: \"in/**/bom.json\"\n"
			dir := project(t, manifest)

			visible := filepath.Join(dir, "in", "classes")
			secret := filepath.Join(dir, "in", "secret")
			for _, d := range []string{visible, secret} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(d, "bom.json"), []byte("{}\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(secret, 0o000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(secret, 0o755) })

			r := rio(t, dir, command)

			requireExit(t, r, ExitUsage)
			// §10: the artifact to go and look at, and the directory that
			// blocked the search.
			requireStderr(t, r, "rcp-client", secret, "could not be fully searched")
			requireNothingWritten(t, dir)
		})
	}
}
