# Разработка

[Документация](README.md) · [SDK](INTEGRATION.md)

## Сборка и проверки

Go 1.26.10+, из корня репозитория:

```sh
go build -o vetroff ./cmd/vetroff
go test -race ./... -count=1 -timeout=120s
go vet ./...
go mod tidy -diff
python3 scripts/check_docs_links.py
python3 scripts/check_core_boundaries.py
python3 -m unittest discover -s scripts -p 'test_*.py'
(cd integration/external && go test -race ./... -count=1 -timeout=90s)
```

Linux NSS: установите `libnss3-dev libnspr4-dev pkg-config`, затем
`go build -tags nss -o vetroff ./cmd/vetroff`.
Для NSS/Neqo:

```sh
python3 scripts/build_neqo.py
. rust/neqo-bridge/target/vetroff-build/env.sh
go build -tags nss,neqo -o vetroff ./cmd/vetroff
```

Версии и происхождение: [Neqo lock](../scripts/neqo.lock.json),
[Mozilla lock](../scripts/mozilla-runtime.lock.json), Cargo.lock и rust-toolchain.toml.
Полная сборка: `python3 scripts/build_mozilla.py --version v0.0.0-ci`; она не публикует релиз.

## Структура и контракты

`cmd/vetroff` — CLI; `vetroff*.go` и `processhost` — SDK;
`internal` — ядро; `experiments` — native runtime и исследовательские стенды.
Runtime не импортирует исследовательские инструменты; исключение — библиотека Necko.
[Wire draft](reference/WIRE-DRAFT-0.md), [negotiation](reference/WIRE-NEGOTIATION.md),
[SDK-контракт](reference/SDK.md) версионируются отдельно от релиза.

## Стабильность XHTTP и TCP Bond

[Обязательный CI](../.github/workflows/stable-xhttp-bond.yml) проверяет Go/NSS,
carriers/scheduling, сбои и ACK, half-close, TLS policy, backpressure и cleanup.
Полная матрица: `VETROFF_STABLE_MATRIX=full`; длительные сессии:
`VETROFF_STABLE_SECONDS=180`. Обычные короткие тесты не заменяют её.
Изменение framing требует новой версии endpoint/capability.

## Выпуски и измерения

[Release workflow](../.github/workflows/release.yml) публикует после version request
в `.github/release-request.json` или тега. Повторная запись существующего релиза запрещена.
Обычный push документации не создаёт новый выпуск.

[Измерения](measurements/) и [реестр evidence](evidence/registry.json) относятся к своим
исходникам и стендам. Loopback не подтверждает WAN/DPI. Экспорт проверенного реестра:
`python3 scripts/evidence_bundle.py --out /private/new-report.json`.
