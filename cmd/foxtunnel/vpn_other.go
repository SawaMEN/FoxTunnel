//go:build !linux

package main

import (
	"context"
	"github.com/SawaMEN/FoxTunnel/internal/linuxvpn"
	"net/http"
)

func vpnCommand(string, []string) error                             { return linuxvpn.ErrNetwork }
func newVPNHub(context.Context, string, bool) (http.Handler, error) { return nil, linuxvpn.ErrNetwork }
