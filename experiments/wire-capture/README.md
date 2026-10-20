# Controlled wire observations

This command is a loopback-only research endpoint, outside runtime packages.
It never forwards a request or retains headers, certificate keys, CID values,
application bytes, raw qlog or pcap. The H2 recorder is `internal/webprofile`;
H3 reads typed quic-go endpoint events for peer effective transport parameters
and initial SETTINGS. The first Initial UDP datagram size is observed on the
socket. QUIC v1 and TLS 1.3 are forced for this controlled comparison.

`python3 scripts/capture_native_wire.py` downloads archive-hash-pinned Firefox
and NaiveProxy, creates fresh browser profiles/certificate DBs, and collects
six observations against this same fixture. FoxTunnel uses pinned NSS for H2
and Neqo for H3. Native browser GET, Naive CONNECT and FoxTunnel CONNECT/POST
are different request methods: comparable scope is cold connection startup,
not page workloads, complete fingerprints or tunnel payload behavior.

Selected QUIC values are effective decoded parameters, including protocol
defaults; original parameter presence, order, unknown extensions and CID bytes
are excluded. H3 SETTINGS are normalized by numeric ID; wire ordering is not
preserved. GREASE/randomized values are retained when exposed by this decoder,
so one observation is not a stable canonical fingerprint.

The runner disables Firefox's content sandbox in its isolated CI fixture and
trusts a short-lived test certificate in that new profile only. This is not a
production browser configuration and never uses an existing profile/account.
Temporary profiles, test keys and logs are deleted; artifacts contain only
metadata and provenance. Version/hash checks fail before executing a replaced
archive; incomplete metadata fails instead of becoming a similarity claim.

Build with `-tags nss,neqo` after the pinned native bridge. Run only on Linux
amd64 with GTK/Firefox dependencies and NSS certutil. See the Neqo workflow.

For H3, Firefox's third-party-root fallback heuristic is disabled because this
fixture uses an imported test CA. Certificate/hostname verification stays on.
This explicit override is recorded in the capture-set manifest.
