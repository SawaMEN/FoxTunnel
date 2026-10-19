# Публичный API для встраивания

**Русский** | [English с примером](SDK.en.md)

Основная поставка — [отдельный версионный бинарник](DISTRIBUTION.md). Для Go также
доступен импорт `github.com/SawaMEN/FoxTunnel`, без доступа к `internal`, запуска
CLI, подпроцесса или зависимости от 3x-ui. Лицензия MIT находится в корне проекта;
API пока экспериментальный, версию/commit следует закреплять.

`NewClient(ClientConfig)` создаёт клиент; `DialContext(ctx,"tcp","host:port")`
возвращает `net.Conn`. Контекст ограничивает установление; после успеха соединение
закрывает вызывающий код. Поддержаны раздельные read/write deadlines со сбросом
после timeout и `CloseWrite` для half-close отправки. Логические адреса относятся
к туннелю. TCP4/TCP6/UDP не принимаются: выбор семейства IP выполняется на выходе.
Padding использует тот же согласованный codec, что и SOCKS, буферы ограничены.

`Client.Close` закрывает соединения/принадлежащие клиенту SOCKS listeners и отменяет
ожидающие прямые подключения. Общий предел ограничивает активные direct/SOCKS
соединения и ожидающие direct dials; переполнение возвращает `ErrCapacity`.
`ServeSOCKS` принимает listener во владение. Конфигурация фиксируется до совместного
использования. Есть CA/SNI/pin, выбор TLS/транспорта, маршрут XHTTP, профиль приёма,
резервные адреса, padding и timeout. Полный API управления bond/cluster в этот
начальный SDK не заявлен; для них остаётся CLI.

`NewServer(ServerConfig)` возвращает `http.Handler`. Приложение управляет TLS 1.3,
сертификатами, HTTP/2, listener limits и остановкой. Plaintext/старый TLS отклоняются;
частные адреса назначения по умолчанию запрещены. Авторизация и ограничения туннелей
остаются в ядре. Собственное шифрование не изобретается.

[Пример встраивания](../../examples/embed/main.go) использует `http.Transport.DialContext`.
[Отдельный внешний модуль](../../integration/external/) проверяет реальный TLS/XHTTP
обмен через публичное API и не может импортировать `internal`. Дополнительно
проверены Go/NSS, пять транспортов, padding, half-close, отмена контекста после
setup, сброс дедлайна, закрытие клиента, лимит и владение SOCKS listener.

Экспериментальные NSS-настройки: `TLSClientProfile: foxtunnel.TLSClientFirefox158`
(только NSS 3.130), отдельно `HTTP2ReceiveProfile: foxtunnel.HTTP2ReceiveFirefox158`.
Профиль локальный, применяется до создания потоков, сохраняется в пулах идентичностей.
[Измерения и ограничения](../research/MOZILLA-CLIENT-PROFILE.md).

Экспериментально для Linux amd64 после [закреплённой сборки Neqo](../research/NEQO-INTEGRATION.md): `Transport: "h3-post", QUICBackend: "neqo", H3Fallback: "h2", QUICHandshakeTimeout: 2*time.Second`. `TLSBackend` — auto/nss; CA/ServerName/SPKIPin сохраняют прежний смысл. Эти поля не включают Neqo в обычных релизах и не меняют формат ссылок.

Управляемый доступ: `NewAccessController`, `AccessPolicy`/`AccessUser`, `ServerConfig.Access`, `Replace`, `Snapshot` и `Close`: [контракт и журнал квот](ACCESS.md).

[Linux TUN VPN: TCP/UDP, DNS, IPv6 и kill switch](../guides/LINUX-VPN.md).
