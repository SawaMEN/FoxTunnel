# Users, revocation and quotas

[Русский](ACCESS.md) | **English**

Stage five adds explicit managed access on Linux. There is no network admin API.
Legacy single-user environment credentials remain supported, mutually exclusive
with managed access. Clients keep the existing Basic credentials/link format;
each account receives its own username and random secret.

## Setup

Create a private directory outside the public web root and a 0600 policy file.
Use at least 24 bytes of high-entropy secret (maximum 1024), preferably generated
with `secrets.token_urlsafe(32)`. Do not reuse the following text as a password.
This creates two real random credentials without printing them:

```sh
install -d -m 700 /etc/foxtunnel/access
umask 077
python3 - <<'PY'
import json, secrets
users = [{"id": name, "username": name, "password": secrets.token_urlsafe(32),
          "max_tunnels": 32, "max_requests": 128,
          "requests_per_second": 100, "burst": 200,
          "quota_bytes": 10737418240}
         for name in ("alice", "bob")]
with open('/etc/foxtunnel/access/users.json', 'x') as f:
    json.dump({"v": 1, "users": users}, f, indent=2)
PY
foxtunnel access --users-file /etc/foxtunnel/access/users.json
unset FOXTUNNEL_USER FOXTUNNEL_PASSWORD
foxtunnel server --listen :443 --cert /etc/foxtunnel/cert.pem \
  --key /etc/foxtunnel/key.pem \
  --users-file /etc/foxtunnel/access/users.json \
  --users-state /etc/foxtunnel/access/usage.json
```

The access command validates the document and prints IDs/disabled/quotas, never
usernames or passwords. Give each client only its own credential using the existing
private environment/link workflow. Rotate short legacy passwords before migration.
Server JSON v1 accepts `users_file`/`users_state` instead of username/password;
both paths are mandatory in CLI managed mode. Policy files must be regular,
private files (0600 or 0400); symlinks/group/world access are rejected. State uses
a 0700 directory and 0600 files. Policy and state cannot be the same file/hardlink.

## Defaults and bounds

| Setting | Default | Scope |
|---|---:|---|
| User `max_tunnels` | 32 | Target sockets, including DNS/dial |
| User `max_requests` | 128 | Active private requests, including carriers and bond RPC/lanes |
| User `requests_per_second` / `burst` | 100 / 200 | Request token bucket, not bytes/second |
| User `quota_bytes` | 0 | Combined target upload/download; 0 means unlimited |
| Root `attempts_per_second` / `attempt_burst` | 200 / 400 | All private attempts, including invalid authentication |
| Root `max_requests` | 1024 | Total active managed private requests |

The example assigns a cumulative 10 GiB allowance, without calendar reset. Bytes
are counted at the destination socket, including reads not yet delivered to the
client. TLS/HTTP/padding overhead and replayed bond records are not charged again.
I/O reserves quota before operations; unused short-I/O budget is returned. At the
quota boundary a stream may close before the last chunk reaches the client. This
is a ceiling, not a guarantee of exactly that many delivered bytes.

Known-user rate/concurrency/quota rejection returns 429. Invalid/revoked credentials
and exhausted global attempt budget use the same public cover/404. Existing
listener, global tunnel, H2/H3, XHTTP and bond bounds remain active. No attacker-
controlled IP/username table grows: at most 1024 configured users and 4096 historic
account IDs. Request limits do not replace listener or bandwidth controls.

## Reload, revoke and rotate

Replace users.json atomically using a 0600 temporary file in the same directory,
validate it with `foxtunnel access --users-file ...`, then `kill -HUP "$FOXTUNNEL_PID"`.
Disable/remove a record to revoke it. Change its random password to rotate while
keeping the stable ID. Changed per-user limits/username also revoke that generation.
Old streams/carriers close; unchanged users retain connections and token buckets.
A malformed, partial, unknown/duplicate-field document or invalid limits reject the
entire reload and retain the current policy. Explicit `users: []` revokes everyone;
missing/null users in the file are invalid.

Stable IDs are 1–64 lowercase `a-z`, digits, `_` or `-`; IDs and usernames are
unique. Accounting survives password changes, removal and re-addition. Do not
change IDs/delete state for routine rotation. A cluster needs the corresponding
policy on all entries and the common exit. Revoking one entry alone does not block
another entry. There is no automatic distributed credential synchronization.

XHTTP UUIDs and bond tokens bind to an account/generation. A different user cannot
attach to that session, and inner WSS/XHTTP requests cannot switch identity. Revoke
closes silent sockets, in-progress dial, carriers and bond sessions. An ordinary
HTTP retry ending does not cancel its shared bond destination.

## Persistence and diagnostics

Before granting data budget, the ledger is fsynced, atomically renamed, then its
parent directory is fsynced. An OS lock allows one writer and releases on process
exit/crash; do not delete the lock file. Failed writes stop access, and corrupt
existing state rejects startup. Use a local filesystem with working fsync/flock.

Refills reserve up to 1 MiB to avoid fsync per packet. After restart, unused reserved
budget is treated as spent: conservative overcharging can include up to 1 MiB plus
unfinished I/O reservations (up to 32 KiB for each active read and write per socket).
Lowering a quota does not retroactively cancel already granted reservations.
Durable `charged_bytes` includes these reservations; exact `bytes_this_process`
starts at zero after restart. This is not monthly billing, distributed storage,
or protection against an administrator rolling back state.

```sh
# Offline, conservative durable charges; requires an existing state file:
foxtunnel access --users-file /etc/foxtunnel/access/users.json \
  --users-state /etc/foxtunnel/access/usage.json
# Live counts in the process log, without credentials:
kill -USR1 "$FOXTUNNEL_PID"
```

There are no automatic request/target/header/link logs. Access parsing/reload
errors do not quote input. Configure any host/reverse-proxy logs separately.

## Bond and SDK

Configure unique-payload quotas on the **common exit** using `--bond-hub`. A
`--bond-upstream` relay enforces credentials/HTTP limits, but must use quota_bytes=0;
nonzero relay quotas are rejected to avoid advertising a bypassable limit. Relays
forward the original user credential. Managed relays reject ordinary CONNECT/POST
exits (including inner carriers), so clients cannot bypass the common exit quota
by disabling bond. Independent exits do not share budgets.

SDK: create `NewAccessController(AccessPolicy{Version:1, Users:[]AccessUser{...}},
stateFile)` and `NewServer(ServerConfig{Access: controller, ...})` without Credentials.
The host owns `Replace`, `Snapshot` and `Close`. Nonempty stateFile enables the
Linux durable ledger/lock; an empty path explicitly chooses volatile accounting.
The host still supplies verified TLS, listener limits and deployment lifecycle.

Tests cover all seven transports and NSS, SOCKS/SDK, revocation/rotation, owner
binding, bond RPC/lane hijack and quota deduplication, concurrent exhaustion,
restart/exclusive ownership/state failure, SIGHUP and redacted diagnostics.
External audit and sustained/platform validation remain later stages.
