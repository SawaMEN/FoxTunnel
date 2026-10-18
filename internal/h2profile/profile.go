// Package h2profile configures actual HTTP/2 receive accounting. It does not
// rewrite frames or implement Firefox/Necko or a TLS fingerprint.
package h2profile

import (
	"net/http"

	"github.com/SawaMEN/FoxTunnel/internal/i18n"
)

const Firefox158 = "firefox-158"

// Observed on Firefox 158 Linux, docs/measurements/2026-10-18. The current
// Go/x/net implementation interprets the connection setting as ADDITIONAL
// credit beyond 65535. Wire tests guard that implementation-specific boundary.
const ConnectionCredit = 12517377
const StreamWindow = 131072
const HeaderTable = 65536

func Validate(name string) error {
	if name != "" && name != "default" && name != Firefox158 {
		return i18n.Error("unknown HTTP/2 receive profile (choose default or firefox-158)")
	}
	return nil
}
func Configure(t *http.Transport, name string) error {
	if err := Validate(name); err != nil {
		return err
	}
	if name != Firefox158 {
		return nil
	}
	t.HTTP2 = &http.HTTP2Config{MaxDecoderHeaderTableSize: HeaderTable, MaxReadFrameSize: 16384, MaxReceiveBufferPerConnection: ConnectionCredit, MaxReceiveBufferPerStream: StreamWindow}
	return nil
}
