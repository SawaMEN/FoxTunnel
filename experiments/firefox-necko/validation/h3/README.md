# Stage 3: native H3 qualification

Status: **4/4 checks complete, 3/6 stages complete**. Qualified code:
`7d4eee64c0acd83daefdaa4c3bd8ab87558bb247`.

- [Source build](https://github.com/SawaMEN/FoxTunnel/actions/runs/40234429164):
  real pinned Gecko C++ build, source lock and all source-workflow gates passed.
- [Runtime qualification](https://github.com/SawaMEN/FoxTunnel/actions/runs/40234867279):
  exact compiled runtime/provenance verification, packaged main CLI/SDK,
  mandatory native tests, resource bounds and wire comparisons passed.
- [Acceptance and hashes](acceptance.json), [artifact metadata](artifacts.json),
  [native results](native-gates.txt), [wire summary](wire-summary.json).
- `managed/` retains all 12 raw managed resource reports; `connect/` retains
  300-second CONNECT reports and efficiency reports; `paired/` retains raw
  60-second baseline/current reports for each protocol. The paired report was
  independently recomputed from those samples and matched exactly.

The 13 mandatory native groups each passed three times. Five optional
research-runtime groups intentionally skip in the bundle-only step after passing
in the earlier research step. This does not mean the mandatory H3 tests skipped.
Negative no-fallback tests cover GET, POST, UDP v1 and UDP v2 with no TCP accepts;
all five sustained H3 modes also record protocol 3 and zero TCP accepts.

All managed modes ran for 60 seconds, then received a six-second idle reclamation
budget before the final measurement. The final helper RSS growth bound is
192 MiB and final descriptor bound is idle plus 16. Sampled peaks remain in the
raw files. All helpers joined and removed their profiles. These are helper-only
loopback observations, not whole-client/WAN results or evidence of statistical
speedup. Wire records compare native CONNECT with full Firefox using the same
patched runtime; randomized extension ordering and JA3 differences are retained.
They do not prove DPI equivalence or a POST/UDP-specific fingerprint match.

The stage-1 and stage-2 validation records remain historical evidence for their
original source locks. ARM64, identity/profile options and unified distribution
packaging remain separate work. No changes are made to `main`.
