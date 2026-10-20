package profile

import (
	"errors"
	"io"
	"os"
	"runtime"
)

// ReadSecretFile rejects symlinks, non-regular inputs and group/world
// readable link files on Unix. A vetroff URI includes the proxy password;
// Base64 encoding provides no confidentiality.
func ReadSecretFile(path string) (Config, error) {
	var empty Config
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return empty, errors.New("connection link file must be a regular private file (no symlinks)")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return empty, errors.New("connection link file must be owner-only (chmod 600)")
	}
	f, err := os.Open(path)
	if err != nil {
		return empty, errors.New("cannot open private connection link file")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return empty, errors.New("connection link file changed during opening")
	}
	return Read(io.LimitReader(f, MaxLinkBytes+1))
}

// WriteSecretFile creates a fresh private file, never follows an existing
// symlink, never overwrites another secret and never prints link contents.
func WriteSecretFile(path, link string) error {
	if path == "" || len(link) > MaxLinkBytes {
		return errors.New("invalid private connection link output")
	}
	if _, err := Decode(link); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create private connection link file")
	}
	_, err = io.WriteString(f, link+"\n")
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		_ = os.Remove(path)
		return errors.New("cannot save private connection link file")
	}
	return nil
}
