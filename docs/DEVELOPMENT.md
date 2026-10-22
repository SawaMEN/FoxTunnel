# Разработка

[Главная](../README.md) · [Интеграция](INTEGRATION.md) · [Эксплуатация](OPERATIONS.md)

## Структура

| Путь | Назначение |
|---|---|
| `cmd/foxtunnel/` | CLI ядра |
| `foxtunnel*.go`, `processhost/` | Публичные API |
| `internal/tunnel/` | Клиент, сервер, SOCKS5 и транспорты |
| `internal/access/` | Управление доступом и учёт |
| `internal/nsstls/` | NSS TLS-адаптер |
| `internal/neqo/`, `rust/neqo-bridge/` | Neqo и runtime FFI |
| `examples/`, `integration/external/` | Примеры и внешний потребитель SDK |
| `experiments/` | Отдельные исследовательские стенды |
| `scripts/`, `.github/workflows/` | Сборка, CI и релизы |

## Сборка и проверки

Из корня репозитория, Go 1.26.10+:

```sh
go build -o foxtunnel ./cmd/foxtunnel
go test -race ./... -count=1 -timeout=120s
go vet ./...
go mod tidy -diff
python3 scripts/check_docs_links.py
python3 scripts/check_core_boundaries.py
python3 -m unittest discover -s scripts -p 'test_*.py'
(cd integration/external && go mod tidy -diff && go test -race ./... -count=1 -timeout=90s)
```

NSS-сборка на Linux требует C-компилятор, pkg-config, NSS/NSPR headers:

```sh
sudo apt-get install libnss3-dev libnspr4-dev pkg-config
go build -tags nss -o foxtunnel ./cmd/foxtunnel
go test -race -tags nss ./... -count=1 -timeout=240s
```

Для Linux amd64 NSS + Neqo:

```sh
python3 scripts/build_neqo.py
. rust/neqo-bridge/target/foxtunnel-build/env.sh
go build -tags nss,neqo -o foxtunnel ./cmd/foxtunnel
go test -race -tags nss,neqo ./... -count=1 -timeout=120s
```

Версии Rust, Neqo, NSS и источники закреплены в
[`neqo.lock.json`](../scripts/neqo.lock.json),
[`mozilla-runtime.lock.json`](../scripts/mozilla-runtime.lock.json),
Cargo.lock и rust-toolchain.toml. Скрипты проверяют их согласованность.
Исправление half-close для classic CONNECT закреплено в `neqo.lock.json`
вместе с SHA-256 патча и обеих версий файла. Сборщик применяет его в приватном
Cargo home; последующие Rust-команды должны использовать созданный `env.sh`.
Для полного Mozilla-архива есть `python3 scripts/build_mozilla.py --version v0.0.0-ci`.
Это отдельный build; команда сама не публикует релиз.

## Протокол и нативные границы

[Wire draft 0](reference/WIRE-DRAFT-0.md) описывает форматы;
[согласование версий](reference/WIRE-NEGOTIATION.md) — необязательное расширение.
Release tag, SDK/process schemas и wire draft версионируются отдельно.
Закрепляйте проверенные версии обоих концов.

NSS выполняет TLS; Go x509 проверяет CA, имя и дополнительные pin до отправки
HTTP-авторизации. HTTP/2 NSS и Neqo используют ограниченные отдельные кэши одноразовых билетов.
Возобновление повторно проверяет CA, имя, срок и VerifyConnection/pinning до
HTTP-данных. NSS 0-RTT отключён; Neqo может передавать ранние H3 control streams,
но HTTP-запросы ждут Connected и проверки. WSS отдельного session cache не имеет.
[Контракт ABI 2 и границы](UPDATE-FIXES.md). Эквивалентность Firefox OCSP
и закрытия TLS не заявляется. Neqo принадлежит одному Go actor на OS thread.
Rust не хранит Go-указатели; буферы заимствуются синхронно на вызов ABI.
Отмена должна вернуть владение и завершить операцию до освобождения памяти.
Объявления находятся в `internal/neqo/bridge.h`.

Runtime не должен зависеть от исследовательских пакетов. Проверка
`check_core_boundaries.py` также запускается с `--tags nss` и `--tags nss,neqo`.
Внешний модуль `integration/external` проверяет только публичный контракт.
Платформенная матрица Go SDK не подтверждает поддержку NSS/Neqo на этих же ОС.

## Измерения и аудит

Исходные результаты сохраняются в [measurements/](measurements/);
[реестр](evidence/registry.json) связывает выбранные файлы с хешами и источниками.
Это исторические результаты конкретных сборок, а не оценка текущего main.

| Инструмент | Проверка |
|---|---|
| `fingerprint_audit.py` | Сопоставление выбранных TLS/H2/H3 метаданных |
| `capture_native_wire.py` | Общий стенд Firefox/NaiveProxy/FoxTunnel |
| `native_backend_metrics.py` | CPU/RSS и loopback-обмен backend-вариантов |
| `field_h2_h3.py`, `bond_stage4_field.py` | Внешние echo-измерения |
| `soak_h2_h3.py`, `operations_soak.py` | Нагрузка и восстановление |
| `optimization_gate.py`, `bond_stage4_gate.py` | Проверка сравнительных отчётов |
| `sdk_evidence.py`, `evidence_bundle.py` | Сводки SDK и пакет для рецензента |

Скрипты находятся в `scripts/`; параметры доступны через `--help`.
Для пакета рецензента укажите новый файл в существующем приватном каталоге:

```sh
python3 scripts/evidence_bundle.py --out /private/new-audit-handoff.json
```

Экспорт проверяет хеши реестра и фиксирует текущий checkout и входы зависимостей.
Это не resolved SBOM или независимый аудит. Внешняя SDK-матрица требует run/pass
всех 22 сценариев; пропуски не засчитываются. См.
[сохранённое происхождение SDK](measurements/2026-10-21/sdk/provenance.json).

[Сравнение wire-метаданных](measurements/2026-10-21/wire/comparison.json)
показывает различия с Firefox. Методы приложений и сценарии различаются;
совпадение отдельных полей не доказывает неразличимость.
[Backend-замеры](measurements/2026-10-21/native-backend-metrics.json)
и [длительная нагрузка](measurements/2026-10-20/native-operations.json)
относятся к указанным в них исходникам и стендам.
Не выдавайте loopback за WAN, задержку HTTP за ping, а ошибки запросов за потерю пакетов.

Независимая проверка безопасности остаётся открытой. Область review:
TLS и авторизация, фильтрация назначений/DNS, квоты и отзыв доступа,
отмена/освобождение ресурсов, FFI и происхождение архивов.
Отчёт должен указывать commit, платформы, build tags, находки и повторную проверку.
Не публикуйте приватные профили, ключи, пользовательский трафик и сырые захваты.

## Стабильность XHTTP и TCP Bond

Поддерживаемые режимы и ограничения описаны в [настройках](FEATURES.md#стабильность-xhttp-и-tcp-bond).
[Workflow XHTTP and Bond stability](../.github/workflows/stable-xhttp-bond.yml)
является обязательной регрессионной матрицей для изменений этих реализаций:

- Пять race-прогонов полного XHTTP/Bond набора на Linux/macOS/Windows.
- 30 сочетаний RPC/lanes, pipeline auto/4/8 и пяти scheduling profiles.
- Native Go: 7 carriers × 3 traffic modes × RPC/lanes = 42 случая.
  NSS: 6 × 3 × 2 = 36 случаев. Каждый проверяет реальные SOCKS/TLS,
  потерю OPEN/write ACK, отказ ingress, payload, один coordinator dial и half-close.
- Reset после prefix во всех XHTTP с padding и без, через DialContext/SOCKS;
  CA/SNI/SPKI, pairing, backpressure, body/gap timeouts и admission limits.
- Восстановление после закрытия negotiated idle lane без redial/replay.
- 100 повторов exploration и реального multi-ingress H2. Раздельные счётчики
  upload/download исключают постоянное вытеснение одного направления другим.
- Held sessions по 180 секунд: три XHTTP и шесть Smart/Adaptive/AutoTune/traffic
  Bond сочетаний. Проверяются целостность, смена метрик, cleanup и reservations.

Обычный `go test` использует двухсекундные held sessions и native mode `auto`.
Полный native matrix включается `FOXTUNNEL_STABLE_MATRIX=full`, длительность —
`FOXTUNNEL_STABLE_SECONDS=180`. Короткий прогон не заменяет длительный CI.
JSON test events сохраняются в CI artifacts на 14 дней. Длительный запуск
задаёт `-parallel=8`, чтобы все шесть Bond сценариев стартовали одновременно
также на runner с четырьмя CPU; длительность каждого остаётся 180 секунд.

Wire endpoints и capability `records-v1` сохраняются. Новое несовместимое framing
требует отдельной версии endpoint/capability. Изменения framing, ACK, лимитов,
дедупликации, TLS policy или cleanup требуют повторения матрицы. EOF в Bond
допустим только для download, а malformed ACK/payload должен завершаться ошибкой.
Стабильность реализации не заменяет отдельный security review или WAN-измерения.

## Настройки протокола и наблюдение

`ClientConfig.RequireProtocolNegotiation` и `ServerConfig.RequireProtocolNegotiation`
включают strict; false сохраняет legacy. Strict требует согласования версии/capabilities до прикладных данных
на обоих концах и несовместим с bond/discovery. Формат: [wire negotiation](reference/WIRE-NEGOTIATION.md).

`Snapshot().Transport.Operations` и `Status().Operations` содержат ограниченные
агрегаты TCP setup, UDP exchange/stream, admission и восстановления.
`WatchStatus` использует те же поля; JSON schema 1 расширена совместимо.
`Active` — незавершённые операции, а не открытые потоки; длительности в
микросекундах. Адресов, credentials, raw errors и payload в этих агрегатах нет.

Текущие [исправления native-адаптеров](UPDATE-FIXES.md) и [история планов](HISTORY.md).
