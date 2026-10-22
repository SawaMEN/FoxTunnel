package tunnel

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/SawaMEN/FoxTunnel/internal/enginestatus"
	"github.com/SawaMEN/FoxTunnel/internal/neqo"
)

// RecordRejection lets SDK admission report local limits into the same bounded
// recorder as the runtime. No error strings, targets or caller labels are used.
func (c *Client) RecordRejection(kind enginestatus.Rejection) { c.status.Reject(kind) }

func operationReason(err error) enginestatus.Reason {
	if err == nil {
		return enginestatus.Success
	}
	if certificateFailure(err) {
		return enginestatus.TrustFailed
	}
	if errors.Is(err, ErrProtocolNegotiation) {
		return enginestatus.ProtocolFailed
	}
	if errors.Is(err, context.Canceled) {
		return enginestatus.Canceled
	}
	var timed net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timed) && timed.Timeout() {
		return enginestatus.Timeout
	}
	if errors.Is(err, neqo.ErrCapacity) {
		return enginestatus.Capacity
	}
	if errors.Is(err, ErrUDPNoResponse) {
		return enginestatus.NoResponse
	}
	var response interface{ HTTPResponseStatus() int }
	if errors.As(err, &response) {
		switch response.HTTPResponseStatus() {
		case 426:
			return enginestatus.ProtocolFailed
		case 429, 503:
			return enginestatus.PeerLimited
		default:
			return enginestatus.PeerRejected
		}
	}
	var network *net.OpError
	var dns *net.DNSError
	if errors.As(err, &network) || errors.As(err, &dns) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return enginestatus.NetworkFailed
	}
	return enginestatus.OtherFailure
}

// UDPResponseError retains only status metadata. Its existing error messages
// stay fixed and contain no response headers, bodies, targets or credentials.
type UDPResponseError struct {
	HTTPStatus int
	Streaming  bool
}

func (e *UDPResponseError) HTTPResponseStatus() int { return e.HTTPStatus }
func (e *UDPResponseError) Error() string {
	if e.Streaming {
		return "UDP streaming endpoint refused (no downgrade to one-shot)"
	}
	return "UDP relay refused"
}
