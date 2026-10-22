# Настройки

[Главная](../README.md) · [Запуск](START.md) · [Диагностика и параметры](CONFIGURATION.md)

Полный список флагов текущей сборки:

```sh
./foxtunnel setup --help
./foxtunnel server --help
./foxtunnel client --help
```

## Транспорты

| `--transport` | Передача |
|---|---|
| `h2-connect` | TCP через HTTP/2 CONNECT; по умолчанию |
| `h2-post` | TCP через HTTP/2 POST |
| `h3-post` | TCP через HTTP/3/QUIC; нужен открытый UDP-порт |
| `h3-connect` | Классический TCP CONNECT через HTTP/3/QUIC; нужен открытый UDP-порт |
| `wss` | HTTP/2 внутри WebSocket/TLS |
| `xhttp-stream-one`, `xhttp-stream-up`, `xhttp-packet-up` | Варианты XHTTP |

Задавайте транспорт при `setup --transport …`. Для `h3-post` и `h3-connect` генератор также
включает H3-слушатель сервера. При ручной настройке сервера нужен `--h3-listen`.
Клиент с `--link-file` использует транспорт из профиля.
`--xhttp-path` и `--xhttp-host` должны соответствовать серверу; Host не меняет TLS SNI.

## Движки

Обычная Go-сборка использует Go TLS и quic-go. Linux-сборка с NSS позволяет
выбрать `--tls-backend nss` для TCP. При `auto` tagged NSS-сборка использует NSS
для TCP, а Go — для H3.

Отдельная Linux amd64 сборка с NSS и Neqo поддерживает `--engine mozilla`:
NSS для TCP/H2, Neqo для H3. Этот флаг не меняет транспорт в профиле.
Неподдерживаемый явно выбранный backend возвращает ошибку.

NSS — TLS-библиотека, Neqo — QUIC/HTTP3-реализация Mozilla. Они не включают весь
сетевой стек Firefox. Автоматический транспорт и H2 fallback движка Mozilla
не повторяют уже отправленный запрос; TLS-ошибка не разрешает обход проверки.

## UDP

UDP выключен по умолчанию. Для нового сервера добавьте `--enable-udp` к
команде `setup`, затем включите его у клиента:

```sh
./foxtunnel client --link-file connection.txt --enable-udp
```

Это SOCKS5 UDP ASSOCIATE с запросом/ответом через HTTPS. Для постоянной
UDP-ассоциации добавьте `--udp-stream`. Сервер должен разрешать UDP в обоих случаях.
Лимиты, время жизни и отмена описаны в [контракте интеграции](INTEGRATION.md).

HTTP/3 как транспорт и передача прикладного UDP — разные настройки.
Ни одна из них сама по себе не включает системный VPN.

## Ноды и Bonding

До восьми явно доверенных входов можно задать через `--server` и повторяемый
`--fallback-server`. Режим `--balance` выбирает вход для новых TCP-соединений:

| Режим | Выбор |
|---|---|
| `failover` | Резервные входы при отказе; по умолчанию |
| `round-robin` | По очереди |
| `least-active` | По числу активных соединений |
| `adaptive` | По недавним успешным ответам, задержке и нагрузке |

Bonding использует несколько входов с **одним общим выходом**. `setup` создаёт
hub; для relay используйте `setup --join-link-file connection.txt`, а его
`node.json` добавьте на hub через `cluster-add --config … --node-file …`.
Проверьте профиль и доверие ко всем нодам до включения:

- `--bond --discover` — Bonding с получением списка нод от hub.
- `--bond-route smart` — прямой hub или один relay к тому же hub.
- `--bond-adaptive` — распределение блоков по подтверждённой скорости и очередям.
- `--bond-autotune` — выбор глубины 4/8; требует `--bond-adaptive`.
- `--bond-traffic auto|latency|throughput` — выбор пути с учётом размера обмена;
  требует `--bond-adaptive`. По умолчанию `legacy`.
- `--bond-lanes` — постоянные каналы и объединение небольших записей.

`--balance adaptive` нельзя совмещать с Bonding. `--bond-route smart` требует
Bonding, discovery и hub среди разрешённых входов. Явный `--bond-pipeline 4|8`
имеет приоритет над автоподбором. Режимы не гарантируют ускорения.

Для UDP v2 отдельно доступен `--udp-multi-node` вместе с `--enable-udp --udp-stream`
и 2–8 доверенными входами. Разные назначения распределяются по нодам; одно
назначение остаётся на одном выходе до конца ассоциации. Режим несовместим
с `--bond`/`--discover`; отказ ноды завершает ассоциацию без скрытого переноса пакетов.

## Дополнительные параметры

`--padding` включает согласованное дополнение первых записей и требует поддержки
на сервере. `--web-root` задаёт публичный статический сайт для обычных запросов;
он должен быть отделён от конфигурации и ключей.

`--engine-status-interval`, `--node-status-interval` и `--bond-metrics-interval`
включают локальную диагностику. Сведения о нодах могут содержать их имена.

Проверка сертификатов всегда обязательна. `--sni` задаёт проверяемое имя,
`--ca-cert` добавляет CA, `--pin-sha256` — дополнительный SPKI pin.
Не публикуйте локальный SOCKS5 без отдельной авторизации. Сервер по умолчанию
запрещает частные и локальные назначения; `--allow-private` предназначен
для контролируемого окружения.

Публичный Go API, UDP, Neqo и Firefox profiles сохраняют отдельный экспериментальный статус. Измерения
на loopback не подтверждают ускорение в Интернете или обход DPI/ТСПУ.

## Стабильность XHTTP и TCP Bond

Все три XHTTP-варианта и TCP Bond RPC/lanes, smart routing, Adaptive, AutoTune
и traffic modes поддерживаются как стабильные возможности. Они включаются явно;
параметры по умолчанию и существующие wire endpoints сохраняются.
`version --json` сообщает их точечный статус в `feature_stability`.
Общий `experimental: true` относится к выпуску/SDK и другим возможностям.

XHTTP использует HTTPS/H2 с Go TLS либо Linux NSS и собственный внутренний
HTTP/2 FoxTunnel. Это не VLESS и не обещание совместимости с Xray.
Bond поддерживается поверх H2 CONNECT/POST, WSS, всех трёх XHTTP и Go H3.
Go-матрица проверяется на Linux/macOS/Windows, NSS — на Linux; статус backend
Neqo этим не меняется.

`CloseWrite` завершает upload с сохранением ответа; отмена/Close освобождает
worker, HTTP requests, paired sessions и reservations. Потеря ACK в Bond
повторяет ту же дедуплицируемую запись на том же hub; XHTTP packet POST после
неоднозначного ACK не переигрывается. Ошибка/reset не должны превращаться в
чистый EOF. Закрытие idle lane допускает повтор той же записи на новом канале
с сохранением hub session и сокета назначения. Upload и download в Adaptive
имеют независимые exploration clocks.

Lanes могут быть медленнее RPC при определённых RTT и очередях. AutoTune
использует goodput подтверждённых HTTP operations, а не свободную полосу.
Отказ общего hub завершает старый TCP session. Стабильный статус не обещает
WAN-ускорения, снижения ping или совпадения fingerprint.
[Обязательная матрица проверок](DEVELOPMENT.md#стабильность-xhttp-и-tcp-bond).
Работа над полным стеком Firefox ведётся отдельно: [этапы ветки firefox](FIREFOX.md).
