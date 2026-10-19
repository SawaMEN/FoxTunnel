# Experimental UDP ASSOCIATE (stage 1)

**English** | [Русский](UDP.md) · [Documentation](../README.en.md)

FoxTunnel offers an **opt-in**, bounded SOCKS5 UDP ASSOCIATE (RFC 1928) that sends a small UDP datagram over one authenticated HTTPS POST and returns the **first** UDP reply. It is **not full UDP VPN support**: there is no TUN, persistent UDP mapping, continuous receiving, QUIC datagram, fragmentation, multicast, or reliability guarantee for voice calls and games. Existing TCP modes are unchanged.

## Enable it

For a manual server: `foxtunnel server ... --enable-udp`. For setup-generated configuration: `foxtunnel setup ... --enable-udp` adds `enable_udp` to the private `server.json`. On the client: `foxtunnel client --enable-udp ...`. This flag is permitted alongside `--link-file` but is **not included** in `vetroff://` links. Public SDK clients and servers expose `ClientConfig.EnableUDP` and `ServerConfig.EnableUDP`. Both default to **false**.

Client UDP cannot be combined with `--bond`/discovery at this stage. H3 requires a working QUIC listener. Keep unauthenticated local SOCKS5 bound to **loopback**.

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
