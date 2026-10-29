# Сравнение Firefox и native-адаптеров: этап 6

Firefox и проверенные NSS/Neqo defaults различаются в resumption и выбранных
TLS/H2/H3 параметрах. В общем loopback GET-сценарии все варианты завершили
нагрузку, отмену потоков и оба переподключения. Это измерение отдельных
свойств транспорта, не доказательство неразличимости для DPI.

## Источник и повторение

Код: `09b80a430ae893c6610cd650024cbf6f2efd9143`, чистый checkout.
[Успешный Neqo CI](https://github.com/SawaMEN/VetroffProxy/actions/runs/39732360445),
artifact `native-wire-observations` ID `12406046986`.
SHA-256 ZIP: `e13f36ab3c43e1c7680811898bcfa060c6be899d0198cffa8c7b6528f9c8ed0f`.

Версии: Firefox 158.0, NSS 3.130, Neqo 0.33.0, Go 1.26.10, Linux amd64.
NaiveProxy 154.0.8037.49 участвует только в прежнем cold metadata capture,
а не в новом общем GET-сценарии. Defaults адаптеров NSS H2/Neqo H3 измерены
без явно заданных `firefox-158` H2/TLS profiles.

[Manifest](manifest.json) содержит SHA-256 архивов, исполняемых файлов,
трёх lock-файлов и каждого исходного наблюдения. Архивы проверяются до
исполнения. Manifest digests проверены при сохранении; сравнение поведения
пересчитано из исходных JSON и совпадает с артефактом.

Workflow `.github/workflows/neqo-experiment.yml` собирает два endpoint:
`experiments/wire-capture` для cold metadata и `experiments/browser-compare`
для общего GET workload. Затем запускается:

```sh
python3 scripts/capture_native_wire.py \
  --endpoint /tmp/native-wire-capture \
  --behavior-endpoint /tmp/browser-compare \
  --out /tmp/native-wire-observations
```

Firefox получает новый NSS DB/profile с доверенным fixture CA. Оба клиента
проверяют обычную цепочку сертификата и localhost SNI. H3 для Firefox
принудительно включён через тестовый Alt-Svc mapping; это override стенда.
Endpoint слушает только IPv4 loopback и не открывает внешних назначений.
Browser background traffic не измеряется. Пользовательские профили, ключи,
HTTP headers и payload не сохраняются в артефакт.

## Поведение под нагрузкой и при переподключении

Один cold GET 64B; ожидание 500 ms для обработки session tickets; три
последовательных GET 64B; восемь параллельных GET по 256 KiB; четыре
прерываемых ответа после получения первых данных; две серверные ротации
с паузой 800 ms и GET 64B после каждой. Завершённые payload проверяются
по длине и содержимому. HTML bootstrap Firefox исключён из workload counts;
он использует первое TLS-соединение до `/cold`. Поэтому `/cold` — название
первой фазы workload, не измерение одинаковой cold-start latency.

| Протокол / клиент | Использованные соединения | Последовательные GET | Завершённые параллельные GET / max active | Отменённые ответы | Resumed после ротаций |
|---|---:|---:|---:|---:|---:|
| H2 / Firefox | 3 | 3 | 8 / 8 | 4 | 2 из 2 |
| H2 / NSS | 3 | 3 | 8 / 8 | 4 | 0 из 2 |
| H3 / Firefox | 3 | 3 | 8 / 8 | 4 | 2 из 2 |
| H3 / Neqo | 3 | 3 | 8 / 8 | 4 | 0 из 2 |

В каждой строке cold/sequential/parallel/cancel использовали соединение 1;
после ротаций — новые соединения 2 и 3. К концу сценария активных запросов
не осталось. TLS resumption взят из `tls.ConnectionState.DidResume` на
сервере; он также проверен положительным Go-контролем с session cache
для H2/H3. NSS/Neqo сохраняют прежнюю политику без resumption; стенд её
не меняет. 0-RTT не измеряется.

Исходные отчёты:
[Firefox H2](firefox-h2-behavior.json),
[NSS H2](vetroff-h2-behavior.json),
[Firefox H3](firefox-h3-behavior.json),
[Neqo H3](vetroff-h3-behavior.json).
[Сводное сравнение](browser-behavior-comparison.json) сохраняет phase counters,
использованные connection IDs и отдельные resumption flags.

## Наличие, значения и порядок выбранных полей

На каждом использованном H2-соединении сохранены ClientHello vectors
и initial SETTINGS в порядке получения. Отчёт отдельно сравнивает наличие,
порядок и значения SETTINGS. В H2 metadata этого прогона dropped frames
и dropped TLS records равны нулю на всех шести соединениях.

| Наблюдение | Firefox | NSS default |
|---|---|---|
| ALPN offer | `h2`, `http/1.1` | `h2` |
| SETTINGS ID order | `1, 2, 4, 5` | `2, 4, 5, 6` |
| SETTINGS initial stream window (ID 4) | 131072 | 4194304 |
| Extension 41 (pre_shared_key) на повторных соединениях | Присутствует, resumption подтверждён сервером | Отсутствует, resumption не наблюдался |

Также различаются выбранные cipher suites, extensions, supported groups,
supported versions, signature algorithms и key-share groups. Их полные
упорядоченные списки приведены в `ordered_h2_connections` и
`first_h2_comparison` сводного JSON. Сравнение cold ClientHello и resumed
ClientHello не используется как доказательство одинакового fingerprint.

Cold H3 metadata получены отдельным одинаковым для обоих клиентов endpoint:
[Firefox H3](firefox-h3.json), [Neqo H3](vetroff-h3.json).
Версия QUIC, ALPN и первый Initial datagram size совпали; выбранные
эффективные transport parameters и H3 SETTINGS различаются. Например:

| Эффективное поле декодера | Firefox | Neqo |
|---|---:|---:|
| max_idle_timeout, ms (ID 1) | 30000 | 90000 |
| initial_max_data (ID 4) | 25165824 | 1048576 |
| disable_active_migration (ID 12) | false | true |
| H3 QPACK table capacity (SETTINGS 1) | 65536 | 4096 |

H3 decoder возвращает выбранные эффективные значения, включая defaults
и sentinels. Raw presence/order QUIC parameters и H3 SETTINGS не измерены
и явно имеют статус `not_measured`; сортировка decoded map не выдаётся за
порядок wire. Cold endpoint и GET workload endpoint — разные режимы стенда.

Прежний cold audit с NaiveProxy сохранён отдельно:
[сравнение cold metadata](comparison.json),
[Firefox H2](firefox-h2.json), [NSS H2](vetroff-h2.json),
[Naive H2](naive-h2.json), [Naive H3](naive-h3.json).
Он использует GET/CONNECT/POST и не считается общим payload benchmark.

## Проверки и исправление стенда

Прошли [Go CI](https://github.com/SawaMEN/VetroffProxy/actions/runs/39732360453),
[NSS CI](https://github.com/SawaMEN/VetroffProxy/actions/runs/39732360596),
[build audit](https://github.com/SawaMEN/VetroffProxy/actions/runs/39732360458),
[Neqo CI](https://github.com/SawaMEN/VetroffProxy/actions/runs/39732360445),
root/external native race-тесты, строгий cgocheck2 и новый positive-control
GET/resumption тест. Python проверяет полноту матрицы, workload counts,
отмены, новые использованные соединения и различие presence/order.

[Первый CI](https://github.com/SawaMEN/VetroffProxy/actions/runs/39731042557)
остановился в Firefox/H3: fixture закрывал QUIC application error code 0.
Локальный повтор с тем же Firefox подтвердил завершение нагрузки/отмен,
но отсутствие первого reconnect после такой ротации. Исправленный стенд
закрывает HTTP/3 с `NO_ERROR` (0x100); два reconnect после этого проходят.
Это исправление fixture, не изменение production-транспорта. При отказе
или таймауте теперь сохраняются промежуточные счётчики без секретов.

Измерения относятся к одному закреплённому browser/runtime и loopback
сценарию. Не измеряются WAN, производительность, полная семантика Necko,
header compression parity, сырые H3 parameter order и классификация DPI.
