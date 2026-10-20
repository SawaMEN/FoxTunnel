# Stage 6/8 — UDP, Linux TUN, DNS, IPv6

> Scope update: FoxTunnel is now a protocol core. Built-in TUN, VPN launchers
> and their CI were removed. TUN/DNS/kill-switch results below are historical;
> host VPN integration must be validated in the client repository. UDP protocol
> work remains in scope. See [integration contract](INTEGRATION.md).

**Режим:** только локальные испытания и GitHub Actions в ветке `up`;
ни один критерий этапа не требует настоящих VDS или WAN.
**Статус: 3 из 5 (60%)**, локальные CI проверены. Подэтап 1 —
отмена SOCKS и DNS guard; подэтап 2 — повторяемый TCP/UDP/DNS
IPv4/IPv6 TUN E2E; подэтап 3 — проверка назначения UDP-ответов,
спуфинга, повреждённых кадров и ограниченной нагрузки.

## Что уже существовало

- `internal/nativetun/linux.go`: локальный Linux TUN c userspace
  gVisor IPv4/IPv6, TCP и UDP forwarding через **локальный SOCKS**;
  маршруты ОС и системный DNS модуль сам не меняет.
- `scripts/linux_tun_companion.py`: необязательная обвязка sing-box
  с DNS detour по SOCKS и **отдельным** nftables OUTPUT guard; при
  аварии клиента guard остаётся активен.
- `scripts/test_linux_tun_e2e.py`: управляемые netns, сервер
  FoxTunnel, проверка TCP/UDP/DNS/IPv4/IPv6/kill-switch.
- Существующие workflow `tun-netns.yml`, `native-tun-e2e.yml`
  прежде запускались автоматически только для `main`, поэтому
  безопасность изменений в `up` проверялась неполно.

**Ограничение:** TUN-модуль — forwarding, не полный VPN kill-switch.
Без nft guard, системных маршрутов и DNS policy он не может обещать
отсутствие прямых соединений со стороны других процессов.

## Подэтап 1: отмена SOCKS-рукопожатий и DNS leak guard

Контекст `net.Dialer.DialContext` раньше защищал лишь фазу TCP connect:
медленный SOCKS5 сервер мог принять соединение, но не отвечать на
приветствие или команду. `ReadFull` продолжал ждать до фиксированного
8-секундного timeout, даже если вызывающая сторона уже отменена.

Добавлены:
- `context.AfterFunc(ctx, conn.Close)` в `dialSOCKS` и
  `dialUDPSOCKS` **только на время handshake** (callback снимается
  перед возвратом успешного соединения; долгоживущий UDP control
  channel не закрывается после завершения вызова).
- Нормализация возникающего при отмене `net.ErrClosed` в
  `context.Canceled` / `context.DeadlineExceeded`.
- `TestStage6SOCKSHandshakeCancellation`: четыре комбинации
  TCP CONNECT/UDP ASSOCIATE × stalled greeting/reply, проверка
  немедленного освобождения TCP-сокета на loopback.
- `TestStage6SOCKSHandshakeDeadlineExceeded`: таймаут с IPv6
  SOCKS destination без локального DNS-запроса.
- Дополнительные настоящие **kernel netns** probes: для
  TCP и UDP DNS 53, DNS-over-TLS TCP 853, QUIC/UDP 8443,
  IPv4/IPv6 в режимах разрешённого TCP и UDP carrier.
  Явно разрешён только зафиксированный IP:port FoxTunnel exit.
- В workflow `tun-netns.yml` и `native-tun-e2e.yml`
  включена ветка `up`; Go-часть native TUN тестируется с `-race`.
  Эти привилегированные тесты создают уникальные изолированные netns
  и **не изменяют** хостовый firewall.

## Подэтап 2: повторные Linux native TUN E2E

В `scripts/test_linux_tun_e2e.py` реальный SOCKS→TUN→HTTPS прокси
проверяется трижды для TCP и UDP на IPv4/IPv6. DNS-запросы A и AAAA
на обеих семьях адресов также повторяются трижды; workflow
`native-tun-e2e.yml` выполняет полную лабораторию два раза,
включая kill-switch и положительную проверку после снятия guard
**внутри изолированного netns**.
Проверено: [Native TUN CI](https://github.com/SawaMEN/FoxTunnel/actions/runs/39441292741).

## Подэтап 3: UDP ASSOCIATE и UDP Stream

Поведение `internal/tunnel/udp_client.go` ужесточено:

- Ответ однократного UDP-запроса должен совпадать с исходным
  числовым IP (с нормализацией IPv4-mapped) **и портом**.
  Раньше сравнивался лишь порт. Для DNS-имени ответ содержит
  числовой IP, полученный на доверенном удалённом узле; локальный
  DNS-запрос клиента для проверки не выполняется.
- `udp_stream_client.go` и `udp_multinode_client.go` теперь
  ведут ограниченный **64 запрошенными адресами на выходной узел**
  список разрешённых ответов. Непрошенные ответы с чужого IP/порта
  отбрасываются; выходы не разделяют разрешения между собой.
- Исходная привязка UDP ASSOCIATE к IP TCP control peer и к
  **первому корректному UDP source port** сохранена. Проверены
  попытки с другого локального UDP-порта, `FRAG != 0`,
  некорректный `ATYP`, превышение `MaxDatagram` и короткие
  пакеты. Невалидные пакеты не занимают источник.
- `ReadFrame` отбрасывает нулевую/слишком большую длину,
  укороченные и фрагментированные кадры с освобождением
  `activeTunnels` после закрытия HTTP stream. Ограничения
  (в частности, 8 одновременных one-shot exchanges, 16 потоков
  назначения и 32 элемента очереди stream) сохранены.
- `TestStage6UDPStreamDropsUnsolicitedRepliesOverH2` использует
  настоящий TLS/H2 транспорт. Тестовый узел посылает ложный ответ
  с другим IP на **тот же порт**, затем корректный ответ: приложению
  доставляется только корректный.
- `TestStage6UDPStreamingReplyGuardBoundedAndConcurrent` проверяет
  отсутствие бесконечного роста allowlist и безопасность конкурентных
  чтений/записей под `-race`.

Проверки: `go test -race ./internal/tunnel -run '^(TestStage6UDP|TestUDPAssociate|TestUDPStream|TestUDPMultiNode)' -count=3`,
`go test ./internal/udpproto -count=5`.
[Stage 6 UDP CI](https://github.com/SawaMEN/FoxTunnel/actions/runs/39443565946).

**Ограничение replay:** UDP не содержит обязательных nonce/sequence-id
с end-to-end anti-replay проверкой; одинаковый пакет с уже разрешённым
IP:port может повториться как в настоящем UDP-соединении. Эти изменения
не являются криптографической anti-replay защитой. DNS-ответ для
доменных запросов проверяется как числовой IP с правильным портом,
но клиент не может локально подтвердить DNS-резолюцию на сервере
без изменения протокола.

## План этапа 6: пять подзадач

- [x] Устранить блокировку отменённых TCP/UDP SOCKS handshakes,
  расширить лабораторную IPv4/IPv6 DNS-deny матрицу и включить
  профильные netns workflows в `up` (после успешного CI).
- [x] Зафиксировать полные локальные E2E TUN-сценарии TCP/UDP/DNS
  для IPv4 и IPv6 с проверкой A/AAAA, повторными прогонами и закрытием
  при аварийной остановке клиента.
- [x] Защитить UDP ASSOCIATE и UDP Stream от неразрешённого IP/порта
  ответа, фрагментов, переполнения пакета и неверного кадра;
  проверить таймауты, привязку источника и конкурентное состояние.
  Криптографическая anti-replay защита не заявлена.
- [ ] Проверить kill-switch и DNS-policy на падение, отмену,
  переподключение, IPv4/IPv6 и отдельно поведение при восстановлении
  сетевого маршрута, без изменения firewall ОС вне netns.
- [ ] Провести ограниченный локальный soak/stress с автоматической
  проверкой утечек сокетов, ресурсов и отката конфигурации;
  задокументировать реальные известные ограничения.

Скрипты, требования и отдельные проверки:
`scripts/test_linux_tun_netns.py`,
`scripts/test_linux_tun_e2e.py`,
`internal/nativetun/stage6_cancel_test.go`.

**Важно:** это не утверждение о защищённости при обрыве сети
на производственных мобильных операторах или о нулевых DNS-утечках
при произвольных настройках системы. Их мы не проверяем.
