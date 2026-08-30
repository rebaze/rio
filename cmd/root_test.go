package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunWritesGreeting(t *testing.T) {
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{})
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() = %v, want nil", err)
	}
	if got := strings.TrimSpace(out.String()); got != "hello from rio" {
		t.Fatalf("output = %q, want %q", got, "hello from rio")
	}
}
