package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/SawaMEN/VetroffProxy/internal/access"
	"github.com/SawaMEN/VetroffProxy/internal/i18n"
)

func readAccessPolicy(path string, relay bool) (access.Document, error) {
	d, err := access.ReadDocument(path)
	if err != nil {
		return d, err
	}
	// A relay cannot meter unique exit payload. Configure durable quotas at the
	// common exit; silently accepting relay-only quotas would allow a bypass.
	if relay {
		for _, u := range d.Users {
			if u.QuotaBytes != 0 {
				return access.Document{}, access.ErrConfig
			}
		}
	}
	return d, nil
}
func accessCommand(args []string) error {
	fs := i18n.NewFlagSet("vetroff access")
	file := fs.String("users-file", "", i18n.Text("private access policy JSON; reload with SIGHUP"))
	state := fs.String("users-state", "", i18n.Text("durable access ledger in a private directory"))
	i18n.Parse(fs, args)
	d, err := access.ReadDocument(*file)
	if err != nil {
		return err
	}
	charged := map[string]int64{}
	if *state != "" {
		if _, e := os.Stat(*state); e != nil {
			return access.ErrState
		}
		charged, err = access.ReadUsage(*state)
		if err != nil {
			return err
		}
	}
	// Offline status is deliberately distinct from live Snapshot/SIGUSR1: it
	// reports conservative durable charges, never fabricated active counts.
	type row struct {
		ID       string `json:"id"`
		Disabled bool   `json:"disabled"`
		Quota    int64  `json:"quota_bytes"`
		Charged  *int64 `json:"charged_bytes,omitempty"`
	}
	rows := make([]row, 0, len(d.Users))
	for _, u := range d.Users {
		var n *int64
		if *state != "" {
			value := charged[u.ID]
			n = &value
		}
		rows = append(rows, row{u.ID, u.Disabled, u.QuotaBytes, n})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return json.NewEncoder(os.Stdout).Encode(struct {
		Users []row `json:"users"`
	}{rows})
}

func checkAccessPaths(users, state string) error {
	clean := func(p string) (string, error) {
		a, err := filepath.Abs(p)
		if err != nil {
			return "", err
		}
		dir, err := filepath.EvalSymlinks(filepath.Dir(a))
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, filepath.Base(a)), nil
	}
	a, err := clean(users)
	if err != nil {
		return access.ErrConfig
	}
	b, err := clean(state)
	if err != nil || a == b || a == b+".lock" {
		return access.ErrConfig
	}
	if ai, e := os.Stat(a); e == nil {
		if bi, e := os.Stat(b); e == nil && os.SameFile(ai, bi) {
			return access.ErrConfig
		}
	}
	return nil
}
