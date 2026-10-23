# Stage 3: full Firefox / Necko CONNECT measurements

The controlled comparison is complete for the pinned Linux amd64 runtime.
It measures Firefox's **raw native CONNECT API**, driven in a full browser
process through Marionette, against the xpcshell SOCKS adapter. The reference
script is independent of the SOCKS parser, local TCP bridge and JS pumps.
Both applications load the same patched libxul and NSS from one verified build.
This is not a comparison with ordinary page navigation or unmodified Firefox.

## Method

Each subject performs four CONNECTs per protocol, three repetitions. Each tunnel
uploads all 132,000 bytes of a deterministic binary pattern, closes its sending
half, then receives and validates every byte and response EOF. The first two
CONNECTs reuse one outer connection. The endpoint closes that connection 200 ms
after its second completed tunnel. Both subjects pause before request three,
retain their process TLS cache and make two further CONNECTs. Each observation
must contain exactly two complete connections per subject and two unique upload
FIN streams per connection. Missing native runtime skips tests and cannot produce
a successful comparison report.

The subjects use the same proxy port, destination, certificate, trust roots,
payload and reconnect policy. Browser reference preferences disable the socket
process (required by raw handoff), background probes and speculative connections;
H3 and the lab root are enabled explicitly. The helper retains its own session
pool cap, setup queue and explicit H3 failure policy. This sequential fixture does
not evaluate their impact on bursts or sustained load.

The H2 endpoint records ClientHello metadata before terminating TLS, then frame
headers, ordered SETTINGS, HPACK block lengths/digests, sanitized decoded field
order, FIN and reset codes. A persistent HPACK decoder includes dynamic-table
reuse and CONTINUATION frames. The H3 endpoint authenticates/decrypts public QUIC
v1 Initial packets and reassembles CRYPTO to parse ClientHello; quic-go exposes
selected effective peer parameters, decoded SETTINGS/headers and stream FIN/reset
events. Initial datagram size is the observed UDP datagram length. No raw packet,
TLS key, ticket, CID, payload or credential value is stored. The Initial decoder
passes the RFC 9001 Appendix A.2 vector, tamper and truncation checks; the H2 parser
passes fragmented header/dynamic-table and redaction checks.

## Results

| Measurement | Observed result in all three repetitions |
| --- | --- |
| H2 ClientHello metadata and ALPN | Equal in the recorded fields |
| H2 SETTINGS, in wire order | Equal: table 65536, push 0, stream window 131072, frame size 16384 |
| H2 HPACK, decoded field order and frame metadata | Equal after fixing the helper User-Agent; first/second header blocks 101/5 bytes |
| H3 ClientHello extension composition and other retained fields | Equal |
| H3 exact TLS extension order and JA3 | Different; both subjects produced three distinct orders for each connection phase, with one stable extension set |
| H3 Initial size, effective QUIC parameters, decoded SETTINGS/headers | Equal |
| Outer connection reuse | Two CONNECTs per connection, then controlled reconnect, for both subjects |
| TLS resumption after reconnect | H3 resumed for both; H2 did not resume for either in this fixture |
| Directional completion | All binary bytes and response EOF verified; two unique upload FIN streams per connection |

The original xpcshell User-Agent ended with `/160.0a1`, while Firefox sent
`Firefox/160.0`. The helper now derives the Firefox product/version from the
native UA's reduced Gecko version, preserving its platform tokens. The
[pre-fix observations](../stage3-before-ua/) and
[comparison](../stage3-before-ua-comparison.json) retain the actual discrepancy:
H2 first HPACK block 97 versus 101 bytes, and different H3 User-Agent fields.
No C++ patch or protocol framing was changed to obtain the post-fix result.

## Evidence and reproduction

- [Six endpoint observations](observations/), including binary and source hashes.
- [Field-by-field comparison and order variability](comparison.json).
- [Runtime provenance and acceptance record](acceptance.json).
- [Complete native/race test output](native-tests.txt): 11 top-level test groups,
  each passed three times, without skips; 100.688 seconds.

From the repository root, with the matching compiled runtime:

```sh
FOXTUNNEL_XPCSHELL=/absolute/path/to/runtime/xpcshell \
FOXTUNNEL_FINGERPRINT_OUT=/absolute/path/to/new-observations \
  go test -race ./experiments/firefox-necko \
    -run '^Test(Fingerprint|GeckoBrowserFingerprint)' -count=3 -v -timeout=180s
python3 scripts/compare_necko_firefox.py \
  --observations /absolute/path/to/new-observations --out /absolute/path/to/new-report.json
```

The [runtime CI verification](https://github.com/SawaMEN/FoxTunnel/actions/runs/39946382981)
passed on `607ed70`. It verified the source lock and runtime hashes, passed the
complete native gates, then repeated the Firefox comparison three times for each
protocol. Its retained-field differences match the local results above. The
`necko-firefox-fingerprint` artifact contains all six CI observations and its
comparison; the acceptance record includes its SHA-256.

The source and runtime workflows archive these observations and their comparison.
The comparator rejects mixed runtime/source versions, incomplete streams,
truncation and insufficient repetitions. It preserves all exact order differences
and adds extension-set comparisons separately; it never computes a similarity
score or treats absent evidence as a match.

## Limits

This is a TLS 1.3-only IPv4 loopback fixture with a private root and pinned patched
runtime. ClientHello metadata excludes random fields, SNI value, key material and
tickets. QUIC transport values are selected decoder-effective values, including
defaults; raw parameter presence/order is not measured. H3 headers are decoded
observations, not QPACK instruction-byte measurements. FIN events can be
retransmitted, so the report compares unique stream IDs. Different extension
orders and JA3 values remain real observations; three repetitions do not establish
equality of probability distributions. Neither metadata agreement nor the use of
a full Firefox process demonstrates Internet packet-shape parity, ordinary
navigation parity, indistinguishability or DPI bypass. Subsequent operational
qualification and the repeated wire comparison are recorded in
[stage 4](../stage4/README.md); that repetition includes an H2 raw HPACK/HEADERS-size
difference absent from this historical measurement.
