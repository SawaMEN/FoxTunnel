# FoxTunnel — каталог документации

**Русский** · [English](README.en.md) · [Главная README](../README.md)

Это **единая точка входа**. Руководства описывают настройку, архитектура — реализацию, справочники — контракты; исследования и замеры отделены от исторических материалов.

> **Текущий статус:** FoxTunnel — экспериментальный TCP-туннель. NSS используется для TCP в поддерживаемых Linux-сборках; H3 по умолчанию — quic-go. Neqo собирается отдельно для Linux amd64. Экспериментальный UDP запрос/ответ включается отдельно; это не полный VPN и не копия Firefox.

## Начните здесь

- [Установка и запуск](guides/SETUP.md)
- [Экспериментальный Linux TUN: sing-box, DNS и nftables](guides/LINUX-TUN.md)
- [Нативный Linux TUN: встроенный gVisor TCP/IP](guides/NATIVE-LINUX-TUN.md)
- [Ссылки подключения](guides/CONNECTION-LINKS.md)
- [Точки входа и публичный сайт](guides/ENDPOINTS.md)

## Как это работает

- [Общая архитектура](architecture/ARCHITECTURE.md)
- [Семь транспортов и TLS backend](architecture/NATIVE-TRANSPORTS.md)
- [XHTTP](architecture/XHTTP.md)
- [UDP ASSOCIATE: возможности, настройки и ограничения](architecture/UDP.md)
- [Кластер и обнаружение нод](architecture/CLUSTER.md)
- [Объединение каналов](architecture/BONDING.md)
- [HTTP/2 receive profile](architecture/H2-RECEIVE-PROFILE.md)
- [Padding](architecture/PADDING.md)
- [Выбор транспортов](architecture/TRANSPORT-STRATEGY.md)

## Контракты и эксплуатация

- [Безопасность](reference/SECURITY.md)
- [Пользователи, отзыв и квоты](reference/ACCESS.md)
- [Публичный SDK](reference/SDK.md)
- [Wire draft 0 (один язык)](reference/WIRE-DRAFT-0.md)
- [Сборки и релизы](reference/DISTRIBUTION.md)
- [Версии и совместимость](reference/COMPATIBILITY.md)

## Исследования и план

- [Актуальные исследования](research/README.md)
- [Сравнение FoxTunnel и VLESS: методика и тестовый стенд](research/TRANSPORT-COMPARISON.md)
- [Измерения и исходные результаты](measurements/README.md)
- [Единая дорожная карта](planning/ROADMAP.md)
- [Исторические обзоры](archive/README.md)

## Где находятся код и эксперименты

- `cmd/` — команды CLI; `foxtunnel.go` — публичный SDK; `internal/` — внутренняя реализация, не API.
- `rust/neqo-bridge/` — отдельная реализация Neqo H3; `experiments/neqo-ffi/` — отдельный UDP-пробник с запретом TLS-аутентификации.
- `scripts/` — закреплённые сборки и проверки; `.github/workflows/` — CI; `docs/releases/` — примечания к выпускам.

**Правило документации:** актуальные инструкции должны соответствовать `main`. Замеры хранятся с датой и без подмены результатов; исторические проекты — в архиве. Не переносите пакеты Go и Cargo.lock только ради внешнего порядка.
