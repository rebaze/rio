//go:build !windows

package evidence

import "os"

func syncDirectory(path string) (err error) {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer func() {
		if e := f.Close(); e != nil {
			err = e
		}
	}()
	return f.Sync()
}
