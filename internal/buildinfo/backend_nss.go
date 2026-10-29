//go:build nss && cgo && linux && !mozilla

package buildinfo

import "github.com/SawaMEN/VetroffProxy/internal/nsstls"

const Flavor = "nss"
const NSSAvailable = true

func linkedNSSVersion() string { return nsstls.Version() }
