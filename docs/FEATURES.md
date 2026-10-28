# Настройки

[Документация](README.md) · [Запуск](START.md)

Параметры задаются при `setup`; клиент с `--link-file` использует профиль.
Полный список: `./vetroff setup --help` и `./vetroff client --help`.

## Транспорты

| `--transport` | Передача |
|---|---|
| `h2-connect` | TCP через HTTP/2 CONNECT; по умолчанию |
| `h2-post` | TCP через HTTP/2 POST |
| `h3-connect`, `h3-post` | HTTP/3/QUIC; нужен UDP-порт |
| `wss` | HTTP/2 внутри WebSocket/TLS |
| `xhttp-stream-one`, `xhttp-stream-up`, `xhttp-packet-up` | XHTTP |

`setup --transport h3-connect` включает H3-слушатель. При ручной настройке сервера
нужен `--h3-listen`. У XHTTP путь и Host должны совпадать с сервером; Host не меняет SNI.

## Движки

Go-сборка использует Go TLS/quic-go. Полный Linux-архив включает NSS и Necko.
`--engine auto` выбирает Necko для совместимых CONNECT, иначе NSS/Go;
`--engine necko` отвергает неподдерживаемые настройки без скрытого переключения.
`--engine mozilla` требует NSS/Neqo для выбранного транспорта.
Доступные backend проверяйте через `version --json`. В Go SDK `Engine: "auto"` включается явно.

Necko поддерживает TCP H2/H3 CONNECT и UDP v1 через H2. UDP streaming, multi-node,
Bond, XHTTP, strict-policy и другие неподдерживаемые сочетания требуют другого backend.

## UDP

Добавьте `--enable-udp` при `setup` и запуске клиента. Для постоянной ассоциации
используйте `--udp-stream`. HTTP/3-транспорт сам по себе не включает прикладной UDP.
`--udp-multi-node` требует UDP streaming и 2–8 доверенных входов; несовместим с Bond/discovery.
Отказ ноды завершает ассоциацию без скрытого переноса пакетов.

## Ноды и Bonding

До восьми входов задаются через `--server` и повторяемый `--fallback-server`.
`--balance`: `failover` (по умолчанию), `round-robin`, `least-active`, `adaptive`.

Bonding объединяет входы с одним общим выходным hub:

- `--bond --discover` — Bonding и получение списка нод.
- `--bond-route smart` — hub напрямую или через один relay.
- `--bond-adaptive` — распределение блоков по измеренной скорости и очередям.
- `--bond-autotune` и `--bond-traffic auto|latency|throughput` требуют adaptive.
- `--bond-lanes` — постоянные каналы.

`setup` создаёт hub. Relay: `setup --join-link-file connection.txt`; его `node.json`
добавляется на hub через `cluster-add --config … --node-file …`.
Smart требует discovery и hub среди доверенных входов; `--balance adaptive` нельзя смешивать с Bond.
Список fallback не создаёт последовательный каскад: [настройка выхода](CASCADE.md).

## Стабильность XHTTP и TCP Bond

Режимы XHTTP и расширенный TCP Bond имеют поддерживаемый контракт;
`version --json` отражает его в `feature_stability`. Это не статус всего SDK или Neqo.
Потеря ACK в Bond допускает дедуплицируемый повтор на том же hub; неоднозначный
XHTTP packet POST не переигрывается. Сбой не должен превращаться в чистый EOF.
Отказ общего hub завершает старую TCP-сессию. Ускорение в WAN не гарантируется.
[Регрессионная матрица](DEVELOPMENT.md#стабильность-xhttp-и-tcp-bond).

Проверка TLS обязательна: `--sni`, `--ca-cert`, `--pin-sha256` уточняют доверие.
`--protocol-policy strict` включает согласование версии и несовместим с Bond/discovery.
`--padding` требует поддержки сервера. `--web-root` храните отдельно от ключей и конфигурации.
