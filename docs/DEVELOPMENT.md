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
go test -race ./... -count=1 -timeout=60s
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
go test -race -tags nss ./... -count=1 -timeout=60s
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
HTTP-авторизации. Сессии/билеты NSS отключены; эквивалентность Firefox OCSP
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
