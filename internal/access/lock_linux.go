//go:build linux

package access

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

func lockState(path string) (func(), error) {
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0077 != 0 {
		return nil, ErrState
	}
	fd, err := unix.Open(path+".lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, ErrState
	}
	f := os.NewFile(uintptr(fd), "access-state-lock")
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, ErrState
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		f.Close()
		return nil, ErrState
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = f.Close() }, nil
}
