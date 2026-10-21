//go:build linux

package tunnel

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAuditCoverRefusesFIFOBeforeOpening(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "public-pipe")
	if err := unix.Mkfifo(pipe, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	done := make(chan error, 1)
	go func() {
		f, _, err := openPublicFile(root, "public-pipe")
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("public FIFO accepted")
		}
	case <-time.After(time.Second):
		// Unblock the baseline's FIFO open so a failing test leaves no goroutine.
		fd, err := unix.Open(pipe, unix.O_RDWR|unix.O_NONBLOCK, 0)
		if err == nil {
			unix.Close(fd)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("public FIFO stalled the handler before its regular-file check")
	}
}
