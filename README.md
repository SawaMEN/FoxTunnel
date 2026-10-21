# FoxTunnel

[English](README.en.md)

FoxTunnel — ядро туннельного протокола на Go. Передаёт TCP и UDP через HTTPS,
работает как отдельный процесс или Go-библиотека. Не зависит от sing-box и Xray.

Клиент предоставляет SOCKS5 на `127.0.0.1:1080`, сервер принимает соединения
и передаёт трафик к назначениям. TUN, маршруты и DNS настраивает приложение-хост.

## Начать

Скачайте полный архив из [Releases](https://github.com/SawaMEN/FoxTunnel/releases)
или соберите обычную Go-версию (Go 1.26.10+):

```sh
go build -o foxtunnel ./cmd/foxtunnel
./foxtunnel version --json
```

Далее — [настройка сервера и клиента](docs/START.md).

## Документация

- [Запуск](docs/START.md) — установка, первое подключение, диагностика.
- [Настройки](docs/FEATURES.md) — транспорты, UDP, несколько нод и Bonding.
- [Интеграция](docs/INTEGRATION.md) — Go API и управление отдельным процессом.
- [Разработка](docs/DEVELOPMENT.md) — сборка, тесты и измерения.
- [Эксплуатация](docs/OPERATIONS.md) — доступ, сертификаты, обновления и релизы.
- [Ветка Firefox](docs/FIREFOX.md) — CONNECT H2/H3 и состояние интеграции Necko.

Основная поставка — Linux amd64/arm64 с NSS; Mozilla/Neqo для Linux amd64
собирается отдельно. Папку `lib/` нужно сохранять рядом с программой.
GUI, APK, DMG и системный VPN-адаптер в поставку не входят.

API и wire-протокол пока экспериментальные: закрепляйте проверенный тег или
коммит. NSS/Neqo не гарантируют отпечаток Firefox или обход DPI.
Лицензия — [MIT](LICENSE).
