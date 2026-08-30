package main

import (
	"os/exec"
	"strings"
	"testing"
)

// "No network access anywhere in the binary, including during schema
// validation" is one of the cross-cutting acceptance criteria, and §12 puts it
// in the README as a promise to the reader. A promise nothing checks is a
// promise that quietly stops being true, so check the import graph.
//
// Absence of an HTTP client is what makes the claim mechanical: the CycloneDX
// schemas are embedded with go:embed and their $refs resolve locally, the p2
// mapping table is embedded, and nothing else has a reason to reach out.
func TestBinaryLinksNoNetworkClient(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
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
	}
	linked := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		linked[strings.TrimSpace(line)] = true
	}

	for _, pkg := range forbidden {
		if linked[pkg] {
			t.Errorf("the binary links %s; rio makes no network calls", pkg)
		}
	}
}
