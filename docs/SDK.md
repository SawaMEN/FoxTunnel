# SDK и процесс: этап 7 из 10

FoxTunnel предоставляет два способа интеграции: Go API и отдельный процесс.
Оба экспериментальны. Закрепляйте проверенный tag/commit и версии обоих концов
wire-протокола. `SDKSchema == 1` описывает семантику API; `process_schema: 1`
описывает события CLI. Это отдельные версии от `foxtunnel-draft-0`, версии
release и schema файла connection link. Изменение wire draft не следует
выводить из номера SDK. Совместимые дополнения могут добавлять поля JSON;
несовместимые семантические изменения требуют нового schema/контракта.

## Go host

Импортируйте `github.com/SawaMEN/FoxTunnel`. `RuntimeInfo()` возвращает реальные
compiled capabilities и build metadata, без подключения к серверу. Поля
`SDKSchema`, `ProcessSchema`, `ProtocolDraft`, `Experimental` доступны host.
Dev build может иметь version `dev`, commit `unknown`, dirty `true`;
это не доказательство происхождения библиотеки. Source identity закрепляет host
через свой module graph/build provenance.

| Операция | Владение и отмена |
|---|---|
| `NewClient(config)` | Не выполняет dial. Настройки фиксируются до конкурентного использования. |
| `DialContext(ctx, "tcp", address)` | ctx ограничивает setup; после успешного возврата поток живёт до Close/deadline. |
| `ServeSOCKSContext(ctx, listener)` | Забирает listener; отмена закрывает этот service и его принятые соединения. Другие direct streams и сам Client продолжают работать. |
| `ServeSOCKS(listener)` | То же владение; служба живёт до закрытия listener или Client. |
| `Client.Close()` | Идемпотентно отменяет pending setup и закрывает принадлежащие streams, associations и listeners. |
| `ExchangeUDP` / `OpenUDP` | Отдельные экспериментальные datagram contracts: [UDP/H3](UDP-H3.md). |
| `NewServer(config)` | Возвращает handler; host владеет сертификатами, TLS/H2/H3 listeners и shutdown. |

Ошибки проверяются через `errors.Is/As`, без разбора локализованного текста:
`net.ErrClosed`, `context.Canceled/DeadlineExceeded`, `ErrCapacity`,
`ErrProtocolNegotiation`; TLS/x509 ошибки остаются причинами ошибок setup.
Длительность `ConnectTimeout` не ограничивает жизнь уже установленного потока.
Не повторяйте запись application bytes после неоднозначного сетевого отказа.

`Snapshot()` возвращает только локальные агрегаты: closed, pending, TCP/UDP
connections, SOCKS listeners, limit и transport status. Counts и transport
snapshot снимаются последовательно, не составляют атомарную транзакцию.
`NodeStatuses()` отдельно содержит node origins: его нельзя автоматически
публиковать в пользовательскую телеметрию как анонимные данные.

`WatchStatus(ctx, interval)` принимает 100ms–1h. Каждый watcher имеет один
buffered sample: новый заменяет непрочитанный. `Sequence` монотонен внутри
подписки; пропуски допустимы. Это sampled state, не журнал всех операций и не
счётчик переданных bytes. Callback на горячем пути отсутствует.
Отмена ctx освобождает watcher и закрывает канал. `Client.Close` публикует
closed snapshot и закрывает канал; cleanup counts ещё могут уменьшаться.
После отмены watcher буфер может содержать последний sample. Host должен
отменять ненужные подписки; каждый watcher использует собственную goroutine/timer.
События не содержат credentials, target/peer addresses, hostnames, raw errors,
HTTP headers или payload. Транспортный статус означает выбор маршрута,
не успешную авторизацию или готовность удалённого сервера.

## Process host без native ABI

`github.com/SawaMEN/FoxTunnel/processhost` импортирует только стандартную
библиотеку и константы контракта. Host не линкует NSS/Neqo. Пример
[`examples/process-host`](../examples/process-host/main.go) запускает проверенный
executable с private connection file и печатает локальный SOCKS address.

~~~go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
child, err := processhost.StartClient(ctx, processhost.ClientOptions{
    Executable: "/verified/bundle/foxtunnel",
    LinkFile: "/private/profile/connection.txt",
})
// Check err. Configure the host packet adapter/HTTP proxy with child.Address.
// On profile switch, cancel ctx and call child.Wait(), or call child.Close().
~~~

Host обязан проверить provenance и целостность полного bundle до запуска.
Supervisor не является sandbox или verifier неизвестного executable. Пути
executable/link должны быть абсолютными; link — private regular file.
Сохраняйте его owner-only permissions/Windows ACL. Пароль не передаётся в argv.
Ambient `FOXTUNNEL_*` environment исключается; child получает credentials из
link file. Дополнительный CA можно указать через `CACertFile`.

Supervisor сначала ограниченно читает `version --json` (8 KiB, deadline 5s),
проверяет product/integration/SDK/process/wire schema, затем запускает client
на `127.0.0.1:0`. Startup ограничен 10s после version check, stdout record — 4 KiB.
В argv передаётся имя secret file, а не его содержимое. Diagnostics stderr
по умолчанию отбрасывается, ошибки supervisor имеют фиксированные коды.
`ready` нужен до использования `Address`. EOF stdin запрашивает штатную остановку;
после 5s зависший child принудительно завершается и reaps. `Close` ждёт reap,
`Done` закрывается после reap, `Wait` возвращает итог. Context `StartClient`
владеет всем временем жизни процесса, не только startup.

## JSON Lines CLI contract

Для `client` и `server` доступны `--events-json` и `--shutdown-on-stdin-eof`.
Для server эти runtime flags можно сочетать с `--config`; для client — с
`--link-file`. EOF shutdown несовместим с `--link-file -`: stdin должен
принадлежать supervisor. Без flags прежний CLI и stdout сохраняются.

Успешный процесс с events flag выдаёт две JSON строки в stdout; diagnostics
остаются на stderr. Записи не содержат user credentials или error text.

~~~json
{"schema":1,"sequence":1,"type":"ready","role":"client","tcp_listen":"127.0.0.1:49152"}
{"schema":1,"sequence":2,"type":"stopped","role":"client","outcome":"shutdown"}
~~~

Server использует `role: server`, а при H3 также `udp_listen` в ready.
`ready` подтверждает успешные bind/config/certificate load и локальный адрес;
он не подтверждает успешный remote handshake, доступность exit, VPN routes,
интернет, authentication или network leak protection. После него host должен
наблюдать процесс и реальные запросы. `stopped` выдаётся после завершения Serve
и закрытия принадлежащих listeners/streams. Outcome — `shutdown` либо
`serve_failed`; последнему соответствует ненулевой exit. При startup failure
ready не выдаётся; crash/kill может не выдать stopped — host проверяет exit.
Не подменяйте эти события разбором локализованных stderr logs.

Unix SIGTERM остаётся штатным shutdown, SIGHUP — reload сертификатов/access.
На Windows переносимый путь — EOF stdin; для остальных изменений server
конфигурации перезапускайте процесс. Host должен постоянно читать stdout,
забирать exit status и освобождать ресурсы при смене профиля.

## Проверки и границы

Внешний модуль `integration/external` импортирует только публичные API. В CI
обязательны 22 случая: прежние 16 HTTP/trust/auth, четыре SDK version/status/
cancellation и два настоящих process-host H2/H3 payload/lifecycle сценария.
CLI строится с race detector на Linux/macOS/Windows. Evidence reducer требует
run/pass каждого случая и успешный пакет; skip или отсутствие binary не проходят.
Отдельные subprocess tests проверяют oversized/несовместимые события,
не-loopback ready, неверную последовательность и kill зависшего child.

Это интеграционный контракт протокольного ядра. TUN, VpnService,
NetworkExtension, socket bypass, DNS, IPv6, kill switch и UI принадлежат
host-приложению. Swift/JNI ABI, готовые Android/macOS приложения и внедрение
в Hiddify/3x-ui здесь не заявляются. Независимый security review остаётся открытым.

## Подтверждённая native матрица

[CI 39540666188](https://github.com/SawaMEN/FoxTunnel/actions/runs/39540666188)
проверил runtime `034b4fc040d699a0824882058bec36b8ecabcad6` на synthetic checkout
`ce1d3d086821b1a9773c58670cc38ff1df2fa46c`. Родители checkout проверены:
base `b124c16a` и runtime head `034b4fc0`. Все три job завершились success.
Original JSON извлечены из CI artifacts; SHA-256 каждого ZIP сверён с digest
GitHub, SHA-256 каждого отчёта сохранён в [provenance](measurements/2026-10-21/sdk/provenance.json).

| Native runner | Обязательные run/pass | Исходный отчёт |
|---|---:|---|
| Ubuntu 24.04 | 22 / 22 | [Linux](measurements/2026-10-21/sdk/external-sdk-ubuntu-24.04.json) |
| macOS 15 | 22 / 22 | [macOS](measurements/2026-10-21/sdk/external-sdk-macos-15.json) |
| Windows latest | 22 / 22 | [Windows](measurements/2026-10-21/sdk/external-sdk-windows-latest.json) |

Каждый отчёт имеет `worktree_dirty: false`, hash фактических go-test events
и полный список обязательных случаев, включая настоящий process-host H2/H3.
CLI собран на runner из проверяемого checkout с race detector. Это 66 выполнений
22 сценариев на трёх ОС; не 66 различных сценариев. Отчёты измеряют указанную
runtime-ревизию, не произвольный future checkout или готовые релизные binaries.
