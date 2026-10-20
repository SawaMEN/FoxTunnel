# FoxTunnel

**[English](README.en.md)**

FoxTunnel — независимое ядро VPN-протокола для встраивания в клиенты и серверные
панели. Передаёт TCP и экспериментальный UDP через HTTPS-транспорты; не зависит
от sing-box или Xray. Это протокол и его реализация, а не отдельное VPN-приложение.

## Интеграция

- **Клиент, например форк Hiddify:** публичный Go API (`NewClient`, `DialContext`,
  `ServeSOCKS`) либо отдельный процесс с локальным SOCKS5. TUN, маршруты, DNS,
  VPN-разрешения, защита внешнего сокета и интерфейс принадлежат клиенту.
- **Панель, например форк 3x-ui:** отдельный серверный процесс с приватным JSON,
  TLS и управляемыми пользователями либо Go `http.Handler` через `NewServer`.
- **[Контракт интеграции](docs/INTEGRATION.md)** — интерфейсы, файлы поставки,
  жизненный цикл и текущие ограничения платформ.

## Релизы

Основная поставка — два архива ядра для **Linux amd64 и arm64 с NSS**.
Внутри: `foxtunnel`, необходимые библиотеки `lib/`, `build.json`,
`integration.json`, `INTEGRATION.md` и лицензии зависимостей.
Сохраняйте структуру архива. Экспериментальный Mozilla/Neqo-вариант имеет
отдельную сборку Linux amd64. [GitHub Releases](https://github.com/SawaMEN/FoxTunnel/releases).

APK, DMG, GUI, системные VPN-установщики и TUN-стек в поставку не входят.
Готовых AAR/XCFramework/C ABI пока нет: интеграция Android/macOS требует отдельного
моста на стороне клиента. Go API и протокол экспериментальные — закрепляйте тег/commit.

## Сборка и проверка интерфейса

```sh
go build -o foxtunnel ./cmd/foxtunnel
./foxtunnel version --json
./foxtunnel server --help
./foxtunnel client --help
```

Команда `client` — адаптер ядра к SOCKS5, `server` — серверная часть протокола.
`setup` и `share` — вспомогательные команды конфигурации и профилей.
Встроенный Linux TUN и VPN-лаунчеры удалены; системной сетью управляет приложение-хост.

## Документация

- [Контракт интеграции](docs/INTEGRATION.md).
- [Ручной запуск ядра](docs/START.md).
- [Транспорты и параметры](docs/FEATURES.md).
- [Архитектура, Go SDK и тесты](docs/DEVELOPMENT.md).
- [Лабораторная дорожная карта без обязательных VDS](docs/ROADMAP-LAB-ONLY.md).

HTTP/2, HTTP/3, WebSocket, XHTTP, NSS/Neqo, несколько нод и управление доступом
сохранены. Измерения в CI не доказывают устойчивость к DPI или готовность
конкретного VPN-клиента к эксплуатации. Лицензия: [MIT](LICENSE).
