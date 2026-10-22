//go:build neqo && cgo && linux && amd64

package neqo

// Eight queued packets, one reader and one actor. Ownership moves through
// channels; a slot is reusable only after the synchronous native call returns.
// This bounds receive storage at ten full-size UDP datagrams per connection.
type datagram struct {
	data [65535]byte
	n    int
}

func datagramPool() chan *datagram {
	free := make(chan *datagram, 10)
	slots := new([10]datagram)
	for i := range slots {
		free <- &slots[i]
	}
	return free
}
