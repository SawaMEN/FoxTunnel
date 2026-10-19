//go:build !linux

package linuxvpn

func OpenTUN(string) (Device, error) { return nil, ErrNetwork }
