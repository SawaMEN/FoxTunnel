# XHTTP и TCP Bond: поддерживаемые режимы

XHTTP и расширенные TCP Bond режимы поддерживаются как стабильные opt-in
возможности protocol-core. Их включение остаётся явным: стабильность контракта
не означает автоматического выбора другого транспорта или ускорения любой сети.
Статус относится к реализации и перечисленным ниже гарантиям, а не к результатам
отложенных интеграций, публичному Go ABI или всему экспериментальному выпуску.

## Поддерживаемая матрица

| Режим | Поддерживаемое поведение |
|---|---|
| `xhttp-stream-one` | Один полнодуплексный H2 POST carrier с внутренним HTTP/2 |
| `xhttp-stream-up` | Связанные upload POST и download GET по одному session ID |
| `xhttp-packet-up` | Последовательные packet POST, ограниченное окно и download GET; ACK после доставки |
| TCP Bond RPC | Один общий hub, 2–8 доверенных ingress, блоки 32 KiB, окно до 8 |
| `--bond-lanes` | Согласованные `records-v1` каналы, объединение малых записей, RPC для старого ingress |
| `--bond-route smart` | Аутентифицированное discovery, прямой hub и доверенный relay к тому же hub |
| `--bond-adaptive` | Раздельные upload/download измерения и периодический выбор ещё не измеренных путей |
| `--bond-autotune` | Автоматический конвейер 4/8 слотов; ручные 4/8 имеют приоритет |
| `--bond-traffic auto/latency/throughput` | Выбор пути по размеру, очереди и подтверждённым измерениям без анализа payload |

XHTTP работает поверх HTTPS/H2 с Go TLS или Linux NSS. Внутри него остаётся
собственный протокол FoxTunnel, а не VLESS и не обещание совместимости с Xray.
TCP Bond проверяется поверх H2 CONNECT/POST, WSS, всех трёх XHTTP и Go H3.
NSS относится к TCP/H2 carriers; статус backend Neqo этим документом не меняется.
Go-матрица исполняется на Linux/macOS/Windows; NSS — на Linux.

## Гарантии и пределы

- До выделения серверной сессии требуются TLS и авторизация; CA/hostname/SPKI
  сохраняются при выборе ingress. Все входы используют один проверенный hub ID.
- XHTTP ограничивает sessions, размер POST, число ожидающих packet и сроки
  незавершённого pairing/body/gap. Неверные, повторные и усечённые записи отвергаются.
- В Bond потерянный ACK повторяет тот же token/sequence/payload. Hub сохраняет
  дедупликацию и tombstones; retry не создаёт новый прикладной поток назначения.
- EOF допустим только для download Bond. Upload/FIN/close требуют корректного ACK;
  некорректный успешный HTTP-ответ считается ошибкой протокола.
- Upload/download exploration имеют отдельные счётчики. Фоновая загрузка одного
  направления не может постоянно занимать все exploration slots другого.
- `CloseWrite` завершает upload и сохраняет ответ. Закрытие/отмена освобождает
  worker, HTTP requests, paired sessions и reservations. Target reset не выдаётся
  за чистый EOF: это проверяется с padding и без, через DialContext и SOCKS.
- XHTTP не повторяет packet после неоднозначного ACK. Bond повторяет только
  собственные дедуплицируемые записи; произвольный TCP CONNECT не переигрывается.
- Поддерживаемый half-close и сетевые deadline описаны в [TCP contract](TCP-CORE.md).
  Download FIN с продолжающимся upload не обещается обычным CONNECT сервером.
- Расширенные TCP Bond режимы требуют совместимых settings: нет padding, adaptive
  balance вместе с Bond или UDP Bond. Ошибка конфигурации должна быть явной.

Lanes могут быть медленнее RPC при определённых RTT/очередях и добавляют HTTP
channels. Adaptive/AutoTune измеряют HTTP exchange goodput, а не свободную полосу.
Отказ общего hub завершает TCP session; новый hub не продолжает старый сокет.
Стабильный статус не обещает выигрыша WAN, более низкого ping или DPI parity.
UDP multi-node, SDK API, Neqo и профиль Firefox имеют собственные статусы.

## Обязательная проверка изменений

[Workflow XHTTP and Bond stability](../.github/workflows/stable-xhttp-bond.yml)
проверяет:

- пять race-прогонов полного XHTTP/Bond набора на каждой из трёх ОС;
- 30 сочетаний RPC/lanes, pipeline auto/4/8 и пяти scheduling profiles;
- полный native matrix: 7 carriers × 3 traffic modes × RPC/lanes = 42 случая Go;
  для NSS — 6 × 3 × 2 = 36 случаев;
- в каждом native случае — реальные SOCKS/TLS, потерю OPEN ACK и write ACK,
  отказ ingress, точное сравнение payload, один coordinator dial и half-close;
- reset после prefix, pairing, backpressure, лимиты, отмену и приватность TLS;
- 100 повторов регрессии exploration/реального multi-ingress H2;
- held sessions по 180 секунд для трёх XHTTP и шести Smart/Adaptive/AutoTune/
  traffic Bond сочетаний, со сменой метрик, проверкой целостности и очистки.

Обычный `go test` выполняет held sessions по две секунды и native mode `auto`.
Полный matrix включается `FOXTUNNEL_STABLE_MATRIX=full`, длительность —
`FOXTUNNEL_STABLE_SECONDS=180`. Короткий прогон не заменяет длительный CI.
JSON test events сохраняются в CI artifacts на 14 дней. Изменения wire framing,
лимитов, дедупликации и cleanup требуют повторения этой матрицы; новое
несовместимое framing требует отдельной версии endpoint/capability.

`version --json` сообщает `feature_stability` для этих режимов. Общий
`experimental: true` продолжает описывать выпуск/SDK и другие возможности;
он не отменяет точечный статус поддерживаемых transport/Bond contracts.

Исторические STAGE/WAN документы сохраняют прежние цели измерений. Их требования
к доказательству ускорения относятся к performance claims и смене defaults;
текущий supported scope и acceptance matrix заданы здесь. Интеграции и отменённый
аудит «200 ошибок» в эту работу не входят.
