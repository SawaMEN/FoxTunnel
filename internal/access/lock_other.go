//go:build !linux

package access

func lockState(string) (func(), error) { return nil, ErrState }
