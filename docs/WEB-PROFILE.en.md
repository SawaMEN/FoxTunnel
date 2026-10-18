# Measuring browser resemblance

[Русский](WEB-PROFILE.md) | **English**

FoxTunnel is not yet indistinguishable from browsing. The goal is to measure
observable differences before changing TLS, HTTP/2, connection reuse or pacing.
Random routes, headers and padding do not establish browser equivalence.

`ft-webprofile` adds a loopback-only TLS 1.3/H2 endpoint. It completes TLS,
serves a fixed HTML page to Firefox, or exercises a real FoxTunnel Client through
SOCKS, its selected native transport, inner H2, authentication and a local TCP
echo destination. It exports ClientHello metadata, initial ordered H2 SETTINGS
and connection WINDOW_UPDATE, the first 512 client frame headers and first 512
TLS record headers (direction, length, time relative to acceptance). Excess event
counts are reported. It retains no record bodies, HPACK, credentials, hostnames,
keys, session IDs or application data in the JSON. A bounded ClientHello prefix
is temporarily replayed into TLS and discarded.

These are **TLS records, not TCP packets**. Times describe socket read/write
observations at the endpoint, not arrival times measured by packet capture. A
record header can be observed before its entire payload arrives. H2 metadata is
available because this controlled endpoint decrypts TLS; an on-path observer
cannot directly read encrypted SETTINGS or HTTP headers. HTTP/1.1, H3, DNS,
TCP segmentation, multi-connection page loading, resumption, ECH interoperability,
mobile Firefox and real operators are outside this fixture.

## Reproduce

Use an isolated browser profile and temporary certificates, never a daily profile.
The fixed fixture credentials are public; the listener deliberately refuses
non-loopback addresses. A connection has a 10-second handshake deadline and a
maximum 30-second observation period (3 seconds by default); Accept expires in
60 seconds. The fixture is not a deployment server.

```sh
go build -o ft-webprofile ./cmd/ft-webprofile
# For NSS: install NSS/NSPR development packages, then build with -tags nss.

mkdir -p /tmp/ft-research/browser
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout /tmp/ft-research/root.key -out /tmp/ft-research/root.pem -days 2 \
  -subj '/CN=Local research CA' -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout /tmp/ft-research/site.key -out /tmp/ft-research/site.csr -subj /CN=localhost
cat > /tmp/ft-research/site.ext <<'EXT'
subjectAltName=DNS:localhost
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
EXT
openssl x509 -req -in /tmp/ft-research/site.csr \
  -CA /tmp/ft-research/root.pem -CAkey /tmp/ft-research/root.key -CAcreateserial \
  -out /tmp/ft-research/leaf.pem -days 2 -extfile /tmp/ft-research/site.ext
cat /tmp/ft-research/leaf.pem /tmp/ft-research/root.pem > /tmp/ft-research/site.pem
certutil -N -d sql:/tmp/ft-research/browser --empty-password
certutil -A -d sql:/tmp/ft-research/browser -n local-research-root -t C,, \
  -i /tmp/ft-research/root.pem

./ft-webprofile --cert /tmp/ft-research/site.pem --key /tmp/ft-research/site.key \
  --source 'Firefox VERSION; OS; fresh profile; local HTML GET' --out firefox.json
# While the listener is running, in a second terminal:
firefox --headless --no-remote --profile /tmp/ft-research/browser \
  --screenshot /tmp/ft-research/page.png https://localhost:8443/

# Once the Firefox capture exits, run a real local FoxTunnel echo workload:
./ft-webprofile --cert /tmp/ft-research/site.pem --key /tmp/ft-research/site.key \
  --sample go --transport xhttp-packet-up \
  --source 'FoxTunnel COMMIT; Go VERSION; OS; 64KiB echo' --out candidate.json
# Repeat with an NSS-tagged binary and --sample nss. Verification stays enabled.
./ft-webprofile --input candidate.json --compare firefox.json --strict
```

`--strict` returns failure if ClientHello or initial H2 fields differ. Equality
only covers those fields; it is not a browsing-flow or censorship-resistance
check. Record sizes and timing depend on workload and must be compared across
matched upload/download sizes, idle periods, RTT/loss and connection lifetimes.

## First live baseline: 18 October 2026

[JSON reports](measurements/2026-10-18/) use official Linux x86_64 Firefox 158.0,
its bundled NSS 3.130, Go 1.26.9 and system NSS 3.98 on the same Linux amd64 host.
Firefox used a fresh research profile with background connectivity/telemetry
services disabled and a locally trusted fixture CA. The container required
content/RDD/GPU sandbox overrides for that isolated headless process; this is
not a normal desktop environment or a recommendation for a daily browser.
FoxTunnel samples use this branch, packet-up and a verified 64 KiB echo. A fourth
sample loads Firefox's NSS 3.130 libraries into the same tagged FoxTunnel binary.
The Firefox page and echo workload intentionally differ: compare initial
negotiation, not total record counts as a classifier-quality metric.

| Field | Firefox 158 | FoxTunnel Go | FoxTunnel NSS 3.98 | FoxTunnel NSS 3.130 |
|---|---|---|---|---|
| ALPN offer | h2, http/1.1 | h2 | h2 | h2 |
| Offered TLS versions | 1.3, 1.2 | 1.3 | 1.3 | 1.3 |
| ClientHello record payload | 1882 B | 1487 B | 194 B | 1390 B |
| Initial H2 SETTINGS in order (ID=value) | 1=65536, 2=0, 4=131072, 5=16384 | 2=0, 4=4194304, 5=16384, 6=10485760 | same as Go | same as Go |
| Initial connection WINDOW_UPDATE increment | 12517377 | 1073741824 | 1073741824 | 1073741824 |

Cipher/group lists, extension order and key shares differ as well. A newer NSS
alone changes the Hello but does not supply Firefox's configuration or Necko's
HTTP/2 behavior. Keep TLS 1.3-only verification policy until a separately
reviewed design changes it; do not advertise unsupported fallback merely to
match a field. JA3 equality would still be insufficient.

Next: integrate and test a pinned Mozilla client stack/configuration, with actual
HTTP/2 flow-control accounting, HPACK and connection reuse; recapture both stacks.
Then use matched normal-page/streaming scenarios and external packet captures to
evaluate length, timing and concurrent connection distributions. Finally measure
success, recovery, throughput and failures on Russian operators. No TSPU bypass
has been demonstrated by these local experiments.

Firefox archive provenance: [official release tarball](https://archive.mozilla.org/pub/firefox/releases/158.0/linux-x86_64/en-US/firefox-158.0.tar.xz),
SHA-256 `9549b054ec4cf85f50f6a19d8c6fb79580312e71ebc4ec2cb217ec9af09dc12a`.

[Follow-up: actual HTTP/2 receive windows and HPACK](H2-RECEIVE-PROFILE.en.md).
