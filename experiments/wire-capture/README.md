# Controlled wire observations

[Development](../../docs/DEVELOPMENT.md)

This loopback endpoint records selected TLS/H2 and endpoint-decoded H3 metadata.
It never forwards requests or saves payload, keys, raw pcap/qlog or connection IDs.

Build with `-tags nss,neqo` after the pinned native bridge on Linux amd64.
`scripts/capture_native_wire.py --help` describes the runner; the workflow
`.github/workflows/neqo-experiment.yml` installs its browser/native dependencies.
The runner verifies pinned Firefox/NaiveProxy archives and uses fresh temporary
profiles with a test CA, IPv4 loopback and verified localhost SNI.
Firefox's content sandbox and third-party-root H3 fallback are adjusted only
inside this isolated fixture.

Firefox GET, NaiveProxy CONNECT and Vetroff CONNECT/POST differ. The comparable
scope is cold connection startup, not full page or tunnel behavior.
H3 values are decoded effective parameters, including defaults/sentinels;
original presence/order and unknown parameters are not preserved.
H3 SETTINGS are normalized by ID. Equality of selected fields does not establish
a complete fingerprint match or DPI resistance.
