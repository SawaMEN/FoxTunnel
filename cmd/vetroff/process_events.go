package main

import (
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/SawaMEN/VetroffProxy/internal/buildinfo"
)

// Two bounded records per run. Errors go to stderr, never into JSON fields.
type processEvent struct {
	Schema    int    `json:"schema"`
	Sequence  int    `json:"sequence"`
	Type      string `json:"type"`
	Role      string `json:"role"`
	TCPListen string `json:"tcp_listen,omitempty"`
	UDPListen string `json:"udp_listen,omitempty"`
	Outcome   string `json:"outcome,omitempty"`
}

func emitProcessEvent(enabled bool, event processEvent) error {
	if !enabled {
		return nil
	}
	event.Schema = buildinfo.ProcessSchema
	return json.NewEncoder(os.Stdout).Encode(event)
}

// The host owns a private stdin pipe: closing it requests graceful shutdown on
// all platforms. Signals remain supported. Input bytes are ignored, never parsed.
func shutdownOnEOF(enabled bool, cancel context.CancelFunc) {
	if enabled {
		go func() { _, _ = io.Copy(io.Discard, os.Stdin); cancel() }()
	}
}
