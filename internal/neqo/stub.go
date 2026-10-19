//go:build !neqo || !cgo || !linux || !amd64

package neqo

const Available = false

func NewTransport(Config) (Transport, error) { return nil, ErrUnavailable }
