# FoxTunnel

**Русский** · [English](README.en.md) · [Вся документация](docs/README.md) · [MIT](LICENSE)

FoxTunnel — **экспериментальный** клиент-серверный TCP-туннель: локальный SOCKS5, удалённый HTTPS-сервер и несколько встроенных способов передачи трафика. Работает без Xray и внешнего proxy sidecar.

> **Статус:** исследовательский прототип, не готовый универсальный VPN. Приложенческий UDP, TUN, управление маршрутами и kill switch ещё не реализованы. Совпадение с сетевым отпечатком Firefox и устойчивость к ТСПУ не доказаны.

## Что работает

| Компонент | Реализация |
|---|---|
| Клиент | Локальный SOCKS5 для TCP, TLS-проверка CA/SNI, необязательный SPKI pin |
| Сервер | HTTPS, TCP-доставка, авторизация, фильтрация назначений, публичная статическая страница |
| Транспорты | `h2-connect`, `h2-post`, `h3-post`, `wss`, `xhttp-stream-one`, `xhttp-stream-up`, `xhttp-packet-up` |
| TLS для TCP | Go TLS; Mozilla NSS по умолчанию в поддерживаемых Linux-сборках с `-tags nss` |
| HTTP/3 | `quic-go` по умолчанию; **экспериментальный opt-in Mozilla Neqo** в отдельной Linux amd64 сборке |
| Дополнительно | Кластер входных нод, bond-каналы, управляемые пользователи/квоты, Go SDK |

**Важно:** NSS для TLS не равен всему Firefox; Neqo для QUIC не переносит Necko или профиль браузера. Существующие реализации HTTP/2 и сервера остаются на Go.

## Единый Mozilla Transport Engine (этап 1)

В клиенте доступен локальный режим `--engine mozilla`. Он выбирает
NSS для TCP/H2 и, если Neqo включён в экспериментальную Linux amd64 сборку,
Neqo для H3. Без NSS режим завершится ошибкой, а не перейдёт на Go TLS.
Ссылка подключения сохраняет указанный сервером транспорт; для ручного
подключения режим автоматически выбирает H3/Neqo или H2/NSS.

~~~sh
foxtunnel client --engine mozilla --link-file connection.txt
~~~

Настройка также доступна через `foxtunnel.ClientConfig.Engine`.
Старые клиенты и команды без флага сохраняют прежнее поведение.
Для Linux amd64 добавлена **отдельная собираемая Mozilla-комплектация** с Go,
NSS и Neqo; её сборка доступна через GitHub Actions `Mozilla unified bundle`
или `python3 scripts/build_mozilla.py --version v0.0.0-ci`.
Это пока артефакт сборки, **не опубликованный релиз**. Тесты на этом этапе не запускались.
Подробности и ограничения: [Mozilla Transport Engine](docs/architecture/MOZILLA-ENGINE.md).

## Быстрый старт из исходников

Нужен **Go 1.26** или новее (в CI используется 1.26.9). Команды выполняются из корня репозитория:

```sh
go test ./...
go build -o foxtunnel ./cmd/foxtunnel
./foxtunnel version --json
```

Для действительного сервера нужны домен, DNS и **действительный сертификат** с закрытым ключом. FoxTunnel не выпускает сертификаты и не настраивает firewall.

```sh
./foxtunnel setup --server https://proxy.example \
  --cert /etc/ssl/proxy/fullchain.pem \
  --key /etc/ssl/proxy/key.pem \
  --out server-config
./foxtunnel server --config server-config/server.json
```

На клиентской машине безопасно передайте созданный файл `server-config/connection.txt` и запустите:

```sh
./foxtunnel client --link-file connection.txt
```

Ссылка **содержит секрет подключения** — не публикуйте её в репозитории или логах. Полная процедура, дополнительные ноды и частный CA описаны в [руководстве установки](docs/guides/SETUP.md).

## Сборки и выбор TLS/QUIC

**Публичные архивы**: Linux amd64/arm64 с NSS, если релиз опубликован на GitHub. Наличие workflow не означает наличия нового релиза. [Форматы архивов и проверка](docs/reference/DISTRIBUTION.md).

**Mozilla Neqo** пока доступен **только при отдельной экспериментальной сборке** для Linux amd64. Он использует проверку CA/SNI/SPKI до авторизации, не поддерживает 0-RTT и не входит в обычные релизы. [Сборка и ограничения Neqo](docs/research/NEQO-INTEGRATION.md). Отдельный пробник `experiments/neqo-ffi` — **не** готовый HTTP/3-клиент.

Выбор `auto` означает NSS для поддерживаемого TCP в Linux NSS-сборке и `quic-go` для H3. При явном указании неподдерживаемого backend должна возвращаться ошибка, а не незаметная замена.

## Документация

- [Начало работы](docs/guides/SETUP.md) · [Ссылки подключения](docs/guides/CONNECTION-LINKS.md) · [Точки входа](docs/guides/ENDPOINTS.md)
- [Архитектура](docs/architecture/ARCHITECTURE.md) · [Транспорты](docs/architecture/NATIVE-TRANSPORTS.md) · [XHTTP](docs/architecture/XHTTP.md) · [Bond](docs/architecture/BONDING.md)
- [Безопасность](docs/reference/SECURITY.md) · [Доступ и квоты](docs/reference/ACCESS.md) · [SDK](docs/reference/SDK.md) · [Протокол](docs/reference/WIRE-DRAFT-0.md)
- [Исследования](docs/research/README.md) · [Измерения](docs/measurements/README.md) · [Дорожная карта](docs/planning/ROADMAP.md)

**Полный каталог, включая исторические документы:** [docs/README.md](docs/README.md).

## Проверки и ограничения

```sh
go test -race ./...
go vet ./...
python3 scripts/check_docs_links.py
```

Результаты loopback-тестов не подтверждают работу в сетях операторов. Перед использованием оцените [модель безопасности](docs/reference/SECURITY.md), [совместимость](docs/reference/COMPATIBILITY.md) и [условия распространения](docs/reference/DISTRIBUTION.md).
