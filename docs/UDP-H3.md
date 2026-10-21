# UDP API and HTTP/3 lifecycle

[Implementation plan](IMPLEMENTATION-PLAN.md) · [Wire format](reference/WIRE-DRAFT-0.md)

The public Go API carries datagrams without a local SOCKS listener. It remains
experimental: pin a tested commit and enable UDP on both client and server.
The host application continues to own TUN, routing, device DNS and outer-socket
protection. No system VPN adapter is introduced.

## API and ownership

- `Client.ExchangeUDP(ctx, Datagram)` performs one v1 request/response exchange.
  Its total budget is at most five seconds, further bounded by ConnectTimeout
  and the caller context. Server HTTP 204 becomes `ErrUDPNoResponse`; an actual
  zero-byte UDP payload is a successful Datagram, not that error.
- `Client.OpenUDP(ctx)` opens a persistent v2 association. `ctx` owns its entire
  lifetime, including after setup. ConnectTimeout bounds only setup (default
  15 seconds). `UDPStreaming` still selects the SOCKS adapter mode; it does not
  gate this explicit v2 API.
- `UDPConn.Send(ctx, Datagram)` serializes complete frames. Cancellation while
  writing closes the association: a partially written frame cannot be retried.
  Already-cancelled calls and invalid addresses/sizes send no frame. A successful
  Send does not promise delivery by UDP or an application response.
- `UDPConn.Receive(ctx)` waits for one permitted datagram. Cancelling this wait
  leaves the association available. Payload storage belongs to the caller.
- Close each association after use. `Client.Close` cancels pending setup,
  closes active UDP associations and unblocks receivers. Native UDP associations,
  one-shot exchanges, TCP connections and pending setup share MaxConnections.

`Datagram{Address: "dns.example:53", Payload: packet}` accepts a hostname or
numeric IP with a decimal port; bracket IPv6, for example `[::1]:53`. Hostnames
resolve only at the exit. Replies contain the resolved numeric IP and port.
Zoned IPv6 addresses are not sent across the wire. `MaxUDPDatagram` is **1232
encoded bytes including the address header**, so maximum payload is 1222 bytes
for IPv4 and 1210 for IPv6. Domains have a variable header. Oversize Send errors
do not invalidate an otherwise healthy association.

```go
// core was created with EnableUDP: true and a compatible transport.
// Keep lifetime alive until the profile stops; do not cancel it after OpenUDP.
lifetime, stop := context.WithCancel(profileContext)
defer stop()
flow, err := core.OpenUDP(lifetime)
if err != nil { return err }
defer flow.Close()
if err := flow.Send(callContext, foxtunnel.Datagram{
    Address: "resolver.example:53", Payload: query,
}); err != nil { return err }
reply, err := flow.Receive(callContext)
// Validate the application response (e.g. DNS transaction ID) at the host layer.
```

## Bounds, failure and clean close

Client v2 receive queues hold at most 32 packets; excess replies are dropped.
The existing per-exit reply guard remembers at most 64 requested destinations.
The server keeps at most 16 destination sockets and 32 queued replies per stream,
with a 30-second idle flow timeout and ten-minute association lifetime. A stable
stream reuses the same destination socket; v1 does not promise NAT continuity.
UDP ordering, duplication and anti-replay beyond the TLS carrier are not provided.

Malformed or truncated v2 framing after HTTP 200 resets the HTTP stream instead
of masquerading as clean EOF. A clean frame-boundary EOF remains clean when the
writer can finish. On cancellation, a response writer that cannot finish within
100 ms receives an immediate write deadline; custom host ResponseWriter wrappers
must forward ResponseController deadlines for that bound. Go H2 and quic-go H3
support them. Teardown joins its response callback before the handler returns.
UDP destination writes are deadline-bounded and cancelled by closing the socket.
One-shot reads also close immediately on cancellation while retaining HTTP 204
for an actual server-side response timeout.

## Network changes and evidence limits

`NotifyNetworkChange` retires cached QUIC generations for future sessions while
preserving active response bodies and their destination mappings. It does not
replay packets, recreate a lost association or promise that a permanently broken
old path can continue. After a failed association the host may open a fresh one;
its destination NAT state is new. No automatic v2-to-v1 downgrade occurs.

The stage-four matrix checks real H2/H3 UDP echo, NSS TCP carriers, Neqo H3,
IPv4/IPv6 loopback when available, synthetic remote DNS, empty/max/oversize
packets, stable v2 source ports, malformed-frame resets, bounded queues, blocked
Send cancellation and client ownership. A stale-path gate verifies that a new
H3 association works after a route signal and the old one works after its path
returns, without replay. Another H3 fixture drops every eleventh packet per
direction and delays writes by 2 ms; target packet counts detect application
replay. Application UDP loss separately times out Receive while preserving the
association. These are deterministic local scenarios, not mobile operator,
Internet MTU, arbitrary NAT, loss-rate throughput or production certification.
