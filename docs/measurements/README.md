# Измерения и исходные данные

**Русский** · [English](README.en.md) · [Каталог](../README.md)

Не подгоняйте сохранённые результаты под текущую версию кода. Файлы относятся к конкретным нагрузкам, платформам, коммитам и датам. Loopback не предсказывает производительность реальной сети.

## 18 октября 2026

Firefox 158, профили Go и NSS, включая H2 receive и XHTTP: [2026-10-18/](2026-10-18/).

## 19 октября 2026

- [Результаты bond и data path](2026-10-19/data-path/README.md) — CPU, аллокации, каналы и задержки.
- [Интероперабельность Neqo](2026-10-19/neqo/README.md) — localhost HTTP/3, потери и запрет UDP.
- [JSON-профили TLS/H2](2026-10-19/) — сравнения NSS/Firefox.

**Методика:** [исследование производительности](../research/PERFORMANCE.md).

## Stage 8 — field HTTP/2 vs HTTP/3

The [field-probe runbook](STAGE8-FIELD-H2-H3.md) separates a working measurement
harness from unavailable independent external measurements. No results are
fabricated from CI loopback tests.

## Stage 10 — Firefox / FoxTunnel / NaiveProxy

[Сравнение TLS/H2 и протокол сбора QUIC/H3](STAGE10-FINGERPRINT.md).
NaiveProxy и сопоставимые H3/QUIC захваты пока отсутствуют.

## Stage 10: actual NSS/H2 measurement

See [Stage 10 methodology and verified CI result](STAGE10-FINGERPRINT.md).
