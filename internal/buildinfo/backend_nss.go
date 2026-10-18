//go:build nss && cgo && linux

package buildinfo

import "github.com/SawaMEN/FoxTunnel/internal/nsstls"

const Flavor = "nss"
const NSSAvailable = true

func linkedNSSVersion() string { return nsstls.Version() }
