package main

import (
	"os/exec"
	"strings"
	"testing"
)

// Explicit delivery may use network clients; normalization and offline delivery
// contracts remain mechanically isolated from client-bearing packages.
func TestOfflinePackagesLinkNoNetworkClient(t *testing.T) {
	args := []string{"list", "-deps"}
	for _, p := range []string{"sbom", "manifest", "discover", "gate", "index", "transform/...", "enrichment", "buildcontext", "delivery", "delivery/record", "evidence"} {
		args = append(args, "github.com/rebaze/rio/internal/"+p)
	}
	out, err := exec.Command("go", args...).Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}

	// net/url and net/netip are parsers with no I/O; jsonschema uses them for
	// format checks. net itself arrives only through spf13/pflag, which
	// defines IP flag types rio never registers, so it is reachable but never
	// reached. An HTTP or RPC client would be a different matter.
	forbidden := []string{
		"net/http",
		"net/http/httptrace",
		"net/rpc",
		"net/smtp",
		"crypto/tls",
		"golang.org/x/net/http2",
		"github.com/rebaze/rio/internal/delivery/dtrack",
		"github.com/rebaze/rio/internal/delivery/runner",
		"github.com/rebaze/rio/internal/cli",
	}
	linked := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		linked[strings.TrimSpace(line)] = true
	}

	for _, pkg := range forbidden {
		if linked[pkg] {
			t.Errorf("offline packages depend on %s", pkg)
		}
	}
}
