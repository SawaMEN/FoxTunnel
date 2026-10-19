# Документация FoxTunnel

Русский — основной язык документации, английский доступен в соседних файлах с суффиксом `.en.md`.

## Начало работы
- [Подготовка и настройка](guides/SETUP.md)
- [Ссылки подключения](guides/CONNECTION-LINKS.md)
- [Серверы и точки входа](guides/ENDPOINTS.md)

- [Linux TUN VPN, DNS и kill switch](guides/LINUX-VPN.md)

## Архитектура и протокол
- [Архитектура](architecture/ARCHITECTURE.md)
- [Нативные транспорты](architecture/NATIVE-TRANSPORTS.md)
- [XHTTP](architecture/XHTTP.md)
- [Кластер](architecture/CLUSTER.md)
- [Объединение путей](architecture/BONDING.md)
- [Padding](architecture/PADDING.md)
- [Транспортная стратегия](architecture/TRANSPORT-STRATEGY.md)
- [HTTP/2-профиль](architecture/H2-RECEIVE-PROFILE.md)

## Справочники
- [Безопасность](reference/SECURITY.md)
- [Публичный SDK](reference/SDK.md)
- [Формат провода](reference/WIRE-DRAFT-0.md)
- [Сборки и релизы](reference/DISTRIBUTION.md)
- [Совместимость](reference/COMPATIBILITY.md)

## Исследования
- [Исследовательские материалы](research/)
- [План интеграции Mozilla Neqo/HTTP3](research/NEQO-INTEGRATION.md)
- [Профиль Mozilla TLS/H2 и отчёт различий](research/MOZILLA-CLIENT-PROFILE.md)
- [Методика измерений](research/PERFORMANCE.md)
- [Передача данных и постоянные bond-каналы](research/DATA-PATH.md)
- [Измерения](measurements/)

## Развитие проекта
- [Дорожная карта](planning/ROADMAP.md)
- [Следующие этапы](planning/NEXT-STEPS.md)
- [Примечания к релизам](releases/)

Исходный код остаётся в `cmd/`, `internal/` и `foxtunnel.go` в корне; `examples/` содержит примеры SDK, `experiments/` — отдельные прототипы. `scripts/` отвечает за сборку и проверку релизов, `.github/workflows/` — за CI.

Не переносите файлы Go-пакетов произвольно: тесты `*_test.go` должны оставаться рядом с кодом, а путь публичного SDK является частью API.

- [Neqo HTTP3: клиент и H2 fallback](research/NEQO-INTEGRATION.md)

Пользователи, отзыв и квоты: [RU](reference/ACCESS.md) / [EN](reference/ACCESS.en.md).
