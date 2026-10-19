package access

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/SawaMEN/FoxTunnel/internal/safejson"
)

type ledger struct {
	Version int              `json:"v"`
	Charged map[string]int64 `json:"charged_bytes"`
}

// ReadDocument never embeds paths, input values or parser excerpts in errors.
func ReadDocument(path string) (Document, error) {
	var d Document
	f, err := privateOpen(path)
	if err != nil {
		return d, ErrConfig
	}
	defer f.Close()
	if safejson.Decode(f, 2<<20, &d) != nil || d.Users == nil || Validate(d) != nil {
		return Document{}, ErrConfig
	}
	return d, nil
}
func privateOpen(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrState
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrState
	}
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		f.Close()
		return nil, ErrState
	}
	return f, nil
}
func ReadUsage(path string) (map[string]int64, error) {
	f, err := privateOpen(path)
	if err != nil {
		if _, e := os.Lstat(path); os.IsNotExist(e) {
			return map[string]int64{}, nil
		}
		return nil, ErrState
	}
	defer f.Close()
	var l ledger
	if safejson.Decode(f, 512<<10, &l) != nil || l.Version != 1 || l.Charged == nil || len(l.Charged) > maxAccounts {
		return nil, ErrState
	}
	for id, n := range l.Charged {
		if !validID(id) || n < 0 || n > 1<<62 {
			return nil, ErrState
		}
	}
	return l.Charged, nil
}
func (c *Controller) persist() error {
	if c.statePath == "" {
		return nil
	}
	l := ledger{Version: 1, Charged: make(map[string]int64, len(c.accounts))}
	for id, a := range c.accounts {
		l.Charged[id] = a.charged
	}
	data, err := json.Marshal(l)
	if err != nil {
		return ErrState
	}
	if atomicWrite(c.statePath, data) != nil {
		c.failed = true
		for _, g := range c.users {
			g.cancel()
		}
		return ErrState
	}
	return nil
}
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".foxtunnel-usage-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if _, err = io.Copy(f, bytes.NewReader(data)); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
