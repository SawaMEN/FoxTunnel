# Main node and one connection link

[Русский](CLUSTER.md) | **English**

The main node publishes the cluster topology and acts as the common exit,
assembling ingress blocks into one destination TCP socket. A `vetroff://` link
needs only its address plus `bond: true` and `discover: true`. The client fetches
trusted ingress origins over authenticated, verified TLS 1.3/H2, then connects
to them directly. One address in the link does not mean one ingress data path.

## Configuration

For generated main/ingress configuration, see [setup / cluster-add](../guides/SETUP.en.md).
Nodes also accept sni/pin_sha256, emitted by setup in public node.json.
Each ingress has independent additive CA/name/pin verification.

Create `cluster.json` on the main node:

```json
{
  "v": 1,
  "nodes": [
    {"url": "https://node-a.example", "weight": 4},
    {"url": "https://node-b.example", "weight": 1},
    {"url": "https://node-c.example", "weight": 2, "disabled": true}
  ]
}
```

Main node:

```sh
./foxtunnel server --listen :443 --cert main.crt --key main.key \
  --web-root /srv/public-site --bond-hub --cluster-file cluster.json
```

Each ingress:

```sh
./foxtunnel server --listen :443 --cert node.crt --key node.key \
  --web-root /srv/public-site --bond-upstream https://main.example
```

All processes use matching `FOXTUNNEL_USER` and `FOXTUNNEL_PASSWORD`, with
valid certificates for their origins. Private CAs use `--bond-ca-cert` on
ingresses and `--ca-cert` on clients. Client NSS remains optional; ingress
connections to the main node use Go TLS. List the main node among `nodes` if
a direct data path is desired. Up to eight entries, including disabled ones;
at least one must be enabled. One enabled entry is degraded single-path mode.

## Connection and changes

```sh
umask 077
./foxtunnel share --server https://main.example --bond --discover > connection.txt
./foxtunnel client --link-file connection.txt
```

Direct CLI: `foxtunnel client --server https://main.example --bond --discover`.
Discovery requires bonding and excludes explicit fallbacks and initial padding.
The link still contains credentials. Older clients reject the unknown
`discover` field; existing explicit-node links remain supported.

Weights are administrator-configured relative capacities, 1..100. The scheduler
scores `(pending requests + 1) * exchange-duration EWMA / weight`, with
demand-driven exploration, randomized cold-start position and five-second failure cooldown. Weights are not
byte quotas; empty read polls do not inflate duration estimates.

Replace the file atomically to update topology/weights. The coordinator rereads
it for each authorized discovery request. Clients refresh on new-stream demand
every 30 seconds and coalesce concurrent refreshes. Unchanged snapshots retain
scheduler measurements. Changes affect new sessions; established sessions keep
their original paths. Drain old sessions before shutting down a removed node.

Snapshots expire after 120 seconds. Transient network failures or HTTP
408/429/503/504 may reuse an unexpired snapshot. TLS/authentication failures,
redirects, HTTP/1 and malformed configuration cannot. The initial connection
requires a reachable main node. Existing streams do not depend on refreshes.

The manifest pins the running exit identity before the first destination dial.
An ingress pointing at another exit is rejected before destination work.
Ingress nodes are trusted TLS endpoints receiving the same credentials;
discovery explicitly delegates this trust to the main node.

## Limits and validation

Topology and reassembly are centralized. CPU, bandwidth and global occupancy
telemetry from all ingresses is not yet collected. Clients schedule from their
own measurements; each server's `--max-tunnels` limits authenticated work and
503 triggers alternative-path retry. Weights are not automatically calculated,
and there is no global allocation between users.

The main exit remains a failure point and bandwidth bottleneck. Losing an
ingress can be tolerated; losing the exit loses its TCP sockets. This change
retains per-block HTTP RPC. Persistent lanes, H3/UDP and DNS transport are
separate work, and TSPU resilience requires field measurements.

Go/NSS integration tests cover one coordinator, two ingresses, SOCKS5, lost
open/ACK responses, ingress failure, byte ordering and TCP half-close. Additional
tests cover weighted outstanding work, cooldown, snapshot refresh/expiry,
authorization, bounded strict JSON and fuzzing. See [bonding](BONDING.en.md).
