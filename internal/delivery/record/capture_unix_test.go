//go:build !windows

package record

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestCaptureRefusesFIFOBeforeOpening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if e := syscall.Mkfifo(path, 0600); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := CaptureRead(path, 1024); done <- e }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("FIFO journal accepted")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("capture blocked opening non-directory source")
	}
}
