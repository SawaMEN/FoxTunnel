//go:build nss && neqo && mozilla && cgo && linux && amd64

package buildinfo

import "github.com/SawaMEN/FoxTunnel/internal/nsstls"

// Mozilla is a dedicated Linux/amd64 distribution flavor that links both
// pinned NSS/NSPR and the pinned Neqo Rust static bridge. Ordinary NSS builds
// keep their existing flavor and code paths.
const Flavor = "mozilla"
const NSSAvailable = true

func linkedNSSVersion() string { return nsstls.Version() }
