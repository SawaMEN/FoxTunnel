# Experimental UDP ASSOCIATE (stage 1)

**English** | [Русский](UDP.md) · [Documentation](../README.en.md)

FoxTunnel offers an **opt-in**, bounded SOCKS5 UDP ASSOCIATE (RFC 1928) that sends a small UDP datagram over one authenticated HTTPS POST and returns the **first** UDP reply. It is **not full UDP VPN support**: there is no TUN, persistent UDP mapping, continuous receiving, QUIC datagram, fragmentation, multicast, or reliability guarantee for voice calls and games. Existing TCP modes are unchanged.

## Enable it

For a manual server: `foxtunnel server ... --enable-udp`. For setup-generated configuration: `foxtunnel setup ... --enable-udp` adds `enable_udp` to the private `server.json`. On the client: `foxtunnel client --enable-udp ...`. This flag is permitted alongside `--link-file` but is **not included** in `vetroff://` links. Public SDK clients and servers expose `ClientConfig.EnableUDP` and `ServerConfig.EnableUDP`. Both default to **false**.

Client UDP cannot be combined with `--bond`/discovery at this stage. H3 requires a working QUIC listener. Keep unauthenticated local SOCKS5 bound to **loopback**.

## Stage 2: persistent multiplexed UDP stream (opt-in)

Use `foxtunnel client --enable-udp --udp-stream ...` to select the **separate** HTTPS endpoint `/.well-known/foxtunnel-udp-stream-v2`. The server's existing `--enable-udp` enables both wire versions. For the Go SDK use `ClientConfig{EnableUDP: true, UDPStreaming: true}`. Selecting `--udp-stream` without `--enable-udp` is rejected.

Each SOCKS5 UDP ASSOCIATE opens **one long-lived, full-duplex HTTP/2 (or HTTP/3) POST**. Its wire format is a two-byte big-endian length followed by a valid RFC 1928 UDP packet, at most **1232 bytes**. It multiplexes multiple destinations over one stream; one UDP request can receive **multiple asynchronous replies**, unlike v1. The server maintains at most **16 connected and DNS/IP-pinned UDP sockets** per association.

An association has a maximum duration of **10 minutes**. A destination socket expires after **30 seconds** of inactivity; the outbound queue holds **32 datagrams** and drops excess. The oldest destination is evicted at capacity. The client pins the UDP source IP and port to the TCP control connection. Authentication, `MaxTunnels`, per-user access metering, DNS/IP filtering and TLS identity verification are retained. There is no fallback to the older wire format after errors.

This is **experimental UDP over reliable HTTP streaming**, which can incur head-of-line blocking when packets are lost. It is **not** QUIC DATAGRAM, TUN, system-level DNS, NAT mobility, multicast, or evidence of resistance to network blocking. Calls and games require independent tests. HTTP/3 and Neqo behaviour requires separate interoperability verification.

Verification: `go test ./internal/udpproto ./internal/tunnel -run 'TestUDP|TestStream' -count=1` and `go test -race ./internal/udpproto ./internal/tunnel`. Tests cover multiple destinations, multiple replies, malformed frames, opt-in admission and the unchanged one-shot v1 relay.

## Safety and wire semantics

- UDP ASSOCIATE owns a TCP control connection. Only datagrams from the same IP address are accepted, the first valid UDP source port is pinned, and closing the control connection closes its UDP socket.
- Each datagram maps to one HTTPS POST to `/.well-known/foxtunnel-udp-v1`. The selected HTTPS transport continues verifying CA/SNI/SPKI, then authenticates with Basic/access credentials **inside TLS**. HTTP/1.1 relay is not supported.
- A complete RFC 1928 UDP packet, including headers, must be ≤ **1232 bytes**; FRAG is 0. Bad reserved fields/address types, empty data, port zero, oversize payloads and fragmented packets are refused. At most **8 concurrent requests** per association.
- Existing `max-tunnels` limits, access quota rules and private destination filtering remain in force. DNS resolves at the server, filtering and pinning the numeric IP **before dial**. Do not enable `--allow-private` on an Internet-facing proxy.
- The server reads only the **first reply** within 3 seconds or a lower configured dial timeout. No response maps to HTTP 204 and no SOCKS UDP response. No request is replayed to another server on failure.
- Connected UDP sockets constrain response sources to the selected IP/port. The relay does not invent Firefox-equivalent traffic shaping.

## Verification

```bash
go test ./internal/udpproto ./internal/tunnel -run 'TestUDP|TestMalformedPackets|TestRoundTrip' -count=1
go test -race ./internal/udpproto ./internal/tunnel
```

The integration test exercises SOCKS5 UDP ASSOCIATE → HTTPS/H2 → local UDP echo plus opt-in refusal. It does **not** test any real ISP. Persistent associations, independently bounded UDP flow control, TUN, routing, DNS and kill switch are later stages. No claimed advantage over VLESS is established.
