# VetroffProxy

Название проекта и CLI — **VetroffProxy** (`vetroffproxy`). Для совместимости путь Go-модуля `github.com/SawaMEN/FoxTunnel`, пакет `foxtunnel`, переменные `FOXTUNNEL_*`, ссылки `vetroff://` и сетевые идентификаторы сохраняются. Старые архивы и результаты измерений сохраняют исходные имена.

[English](README.en.md)

VetroffProxy — ядро туннельного протокола на Go. Передаёт TCP и UDP через HTTPS,
работает как отдельный процесс или Go-библиотека. Не зависит от sing-box и Xray.

Клиент предоставляет SOCKS5 на `127.0.0.1:1080`, сервер принимает соединения
и передаёт трафик к назначениям. TUN, маршруты и DNS настраивает приложение-хост.

## Начать

Скачайте полный архив из [Releases](https://github.com/SawaMEN/FoxTunnel/releases)
или соберите обычную Go-версию (Go 1.26.10+):

```sh
go build -o vetroffproxy ./cmd/vetroffproxy
./vetroffproxy version --json
```

Далее — [настройка сервера и клиента](docs/START.md).

## Документация

- [Запуск](docs/START.md) — установка, первое подключение, диагностика.
- [Настройки](docs/FEATURES.md) — транспорты, UDP, несколько нод и Bonding.
- [Интеграция](docs/INTEGRATION.md) — Go API и управление отдельным процессом.
- [Параметры и диагностика](docs/CONFIGURATION.md) — offline-проверка и doctor.
- [Разработка](docs/DEVELOPMENT.md) — сборка, тесты и измерения.
- [Эксплуатация](docs/OPERATIONS.md) — доступ, сертификаты, обновления и релизы.
- [Прогресс и история](docs/HISTORY.md) — планы, update и исходные замеры.
- [Ветка Firefox](docs/FIREFOX.md) — CONNECT H2/H3 и состояние интеграции Necko.

В ветке `xfd` релиз собирается одним архивом для каждой архитектуры: Linux amd64
включает NSS и полный Necko, Linux arm64 — NSS (без полного Necko).
Вариант amd64 выбирает Necko автоматически для совместимых CONNECT, для других
режимов использует NSS/Go. Храните весь каталог установки, включая `lib/` и `runtime/`.
GUI, APK, DMG и системный VPN-адаптер в поставку не входят.

Публичный Go API пока экспериментальный: закрепляйте проверенный тег или коммит.
XHTTP и расширенные TCP Bond режимы имеют [стабильный поддерживаемый контракт](docs/FEATURES.md#стабильность-xhttp-и-tcp-bond). NSS/Neqo не гарантируют отпечаток Firefox или обход DPI.
Лицензия — [MIT](LICENSE).

Каскадный выход TCP/UDP и DNS через SOCKS5: [настройка и ограничения](docs/CASCADE.md).
