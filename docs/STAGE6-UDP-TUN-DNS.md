# Stage 6/8 — UDP, Linux TUN, DNS, IPv6

**Режим:** только локальные испытания и GitHub Actions в ветке `up`;
ни один критерий этапа не требует настоящих VDS или WAN.
**Подэтап 1 из 5**: fail-closed отмена TCP/UDP SOCKS handshakes и
изоляция физического DNS для IPv4/IPv6. Статус подэтапа подтверждается
CI, а не наличием коммита.

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

## План этапа 6: пять подзадач

- [x] Устранить блокировку отменённых TCP/UDP SOCKS handshakes,
  расширить лабораторную IPv4/IPv6 DNS-deny матрицу и включить
  профильные netns workflows в `up` (после успешного CI).
- [ ] Зафиксировать полные локальные E2E TUN-сценарии TCP/UDP/DNS
  для IPv4 и IPv6 с проверкой настоящих DNS-ответов,
  повторными прогоном и корректным закрытием сессий.
- [ ] Разобрать UDP ASSOCIATE и UDP stream на ошибочные адреса,
  фрагментацию, spoofing/replay, overflow, таймаут и многопоточность.
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
