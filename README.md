# VetroffProxy

[English](README.en.md)

TCP и UDP через HTTPS. Клиент поднимает SOCKS5, сервер передаёт трафик к назначениям.
Работает как CLI `vetroff` или Go-библиотека, без sing-box и Xray.

## Быстрый старт

Используйте клиент и сервер из одной сборки. Первоначальные архивы v0.1.0
до очистки namespace несовместимы с main; точный коммит указан в описании релиза.

Нужны сервер, домен и TLS-сертификат. Скачайте полный Linux-архив из
[Releases](https://github.com/SawaMEN/VetroffProxy/releases) или соберите CLI:

```sh
go build -o vetroff ./cmd/vetroff
./vetroff version
```

Для сборки нужен Go 1.26.10+. Далее — [запуск сервера и клиента](docs/START.md).

## Возможности

- HTTP/2, HTTP/3, WebSocket и XHTTP.
- UDP, несколько нод, Bonding и выход через SOCKS5-каскад.
- Go TLS/quic-go; NSS и Necko в соответствующих Linux-сборках.

[Документация](docs/README.md) · [Настройки](docs/FEATURES.md) · [Go SDK](docs/INTEGRATION.md)

TUN и маршрутизацию настраивает приложение-хост. Протокол и SDK экспериментальные;
обход DPI и совпадение с Firefox не гарантируются.

[MIT](LICENSE)
