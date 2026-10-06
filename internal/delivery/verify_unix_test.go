//go:build !windows

package delivery

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadBoundedRejectsFIFOWithoutBlocking(t *testing.T) {
	if p := os.Getenv("RIO_TEST_FIFO"); p != "" {
		if _, e := ReadBounded(p, 1024); e == nil {
			os.Exit(2)
		}
		return
	}
	p := filepath.Join(t.TempDir(), "fifo")
	if e := syscall.Mkfifo(p, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReadBoundedRejectsFIFOWithoutBlocking$")
	cmd.Env = append(os.Environ(), "RIO_TEST_FIFO="+p)
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("nonregular input blocked or was accepted: %v %s", e, b)
	}
}
