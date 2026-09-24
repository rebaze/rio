//go:build !windows

package delivery

import (
	"os"
	"syscall"
)

// O_NONBLOCK also prevents a regular-file-to-FIFO replacement from hanging
// between path inspection and the descriptor's own regular-file check.
func openRegular(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
