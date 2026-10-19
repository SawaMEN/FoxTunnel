# FoxTunnel roadmap

[Русский](ROADMAP.md) · **English** · [Documentation](../README.en.md) · [Source](https://github.com/SawaMEN/FoxTunnel/tree/main)

The **single current roadmap**, replacing the duplicated `NEXT-STEPS` file. Reviewed **19 October 2026**. “Implemented” means merged into `main`, **not** production-ready.

## Implemented in source

| Stage | Current scope | Details |
|---|---|---|
| 1. Reproducible foundation | Build verification; releases triggered independently | [Distribution](../reference/DISTRIBUTION.en.md), [compatibility](../reference/COMPATIBILITY.en.md) |
| 2. Mozilla TLS/H2 | NSS TCP and measured profile gaps; **no full Firefox parity** | [Mozilla profile](../research/MOZILLA-CLIENT-PROFILE.en.md) |
| 3. Data path | Bounded bond lanes, coalescing and loopback benchmarks; no claimed Internet advantage | [Bond](../architecture/BONDING.en.md), [data path](../research/DATA-PATH.en.md) |
| 4. Neqo/H3 | Experimental Linux amd64 client with CA/SNI/SPKI and narrowly scoped H2 fallback; quic-go remains the default | [Neqo](../research/NEQO-INTEGRATION.en.md) |
| 5. Access control | Local users, revocation/rotation and quotas; no distributed control plane | [Access](../reference/ACCESS.en.md) |

These stages are merged into `main`. Passing CI on their source branches does **not** prove every combined-commit check passed: review the current GitHub Actions checks. NSS and Neqo experiments are not production readiness claims.

## Next

1. **Full VPN:** application UDP, TUN, routes, DNS/IPv6 and kill switch; include leak and failure tests.
2. **Operations:** installation, updates/rollback, target OS, soak and native-memory tests, independent security review.
3. **Field measurements:** comparable Firefox/NaiveProxy/FoxTunnel workloads, packet captures, RTT/loss, networks and reproducible evidence.
4. **Integrations:** further client/panel adapters after API and wire contracts are stabilized.

## Acceptance rules

- **Code is not a release:** verify GitHub Releases before claiming an artifact exists.
- **NSS is not Firefox:** shared libraries do not replicate Necko or browser-level HTTP/2 behavior.
- **Neqo is not a censorship-resistance guarantee:** neither TSPU bypass nor superiority to NaiveProxy has been established.
- New backends require fail-closed trust, no silent downgrade, interoperability tests, race tests and bounded resources.
