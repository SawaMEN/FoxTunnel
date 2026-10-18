//go:build !nss || !cgo || !linux

package buildinfo

const Flavor = "go"
const NSSAvailable = false

func linkedNSSVersion() string { return "" }
