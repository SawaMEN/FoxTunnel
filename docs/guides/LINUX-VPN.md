# Шестой этап: экспериментальный Linux TUN VPN

[English](LINUX-VPN.en.md)

Режим `ip-v1` переносит IP-пакеты через существующий проверенный TLS/HTTP-транспорт
FoxTunnel. TCP, UDP, фрагментацию и ICMP обрабатывает ядро Linux на обоих концах.
Не нужен отдельный userspace TCP stack или внешний tun2socks. DNS идёт через тот
же TUN. Поддерживаются IPv4 и IPv6, MTU 1280. Обычный SOCKS/TCP не меняется.

Это экспериментальный **L3 поверх надёжного потока**, включая H3 streams, а не
QUIC DATAGRAM, CONNECT-IP RFC 9484 или CONNECT-UDP RFC 9298. На TCP-транспорте
есть TCP-over-TCP и head-of-line blocking; выигрыш скорости не заявляется.
Локальный VPN не подтверждает маскировку Firefox или доступность у операторов.

## Требования

- Linux, `/dev/net/tun`, root/CAP_NET_ADMIN; серверу нужны TUN и NAT.
- `iproute2`, `nftables`; клиенту также работающий `systemd-resolved`/`resolvectl`.
- Управляемые пользователи пятого этапа; ID в VPN-конфигурации совпадает с `id`
  пользователя. Одна активная IP-сессия на ID. Legacy-credentials и relay для
  IP-сервиса не подходят. IP-сессия идёт прямо к настроенному выходу.
- Один буквальный IP endpoint в закрытом файле `vetroff://`, явный проверяемый SNI,
  действительный CA и при необходимости SPKI pin. Bootstrap DNS не используется.
  Bond, discovery, padding и автоматический обход на прямую сеть запрещены.
- Для первого эксперимента — отдельные Linux-машины/VM. Клиентский kill switch
  блокирует прямой выход всей машины, включая существующий SSH вне VPN.

Все JSON/файлы ссылок — обычные файлы 0600 вне public web root, без симлинков.
Конфигурация VPN отдельная; меняйте адреса только при остановленных сессиях.

## Сервер

Уже настроенные сертификаты и [users.json/usage.json](../reference/ACCESS.md)
сохраняются. Пример `/etc/foxtunnel/vpn-server.json`:

```json
{
  "v": 1,
  "underlay": "eth0",
  "peers": [{"id":"alice","ipv4":"100.96.0.2","ipv6":"fd62:666f:78::2"}]
}
```

Адреса пользователей должны быть уникальными, из `100.96.0.0/24` и
`fd62:666f:78::/64`; до 128 peers. Не используйте эти диапазоны в другой локальной
сети. `underlay` — фактический интерфейс выхода VDS в Интернет.

Включите forwarding осознанно, по политике вашей машины, и установите отдельную
таблицу nftables (сохранение sysctl после reboot — задача оператора):

```sh
sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
foxtunnel vpn-network --config /etc/foxtunnel/vpn-server.json
unset FOXTUNNEL_USER FOXTUNNEL_PASSWORD
foxtunnel server --listen :443 \
  --cert /etc/foxtunnel/cert.pem --key /etc/foxtunnel/key.pem \
  --users-file /etc/foxtunnel/access/users.json \
  --users-state /etc/foxtunnel/access/usage.json \
  --vpn-config /etc/foxtunnel/vpn-server.json
```

Сервис откажется запускаться без forwarding и таблицы `inet foxtunnel_vpn_server`.
Она делает NAT44/NAT66 на underlay, запрещает TUN → локальный сервер/другие peers,
принимает обратные established/related потоки. Чужие таблицы/цепочки не очищаются.
Существующая политика DROP другого firewall может по-прежнему запрещать VPN:
согласуйте её с вашей конфигурацией, код не обходит чужие запреты.

На сессию создаётся непостоянный TUN `ftvs<hash>` и два маршрута /32 и /128.
При закрытии FD интерфейс и его маршруты удаляет ядро. Запрос проверяется до
выделения интерфейса. Повторный вход того же ID получает 409 до закрытия прежнего.
Отзыв/ротация пятого этапа отменяют и IP-сессию. Общие лимиты и квоты сохраняются.

## Клиент

Сначала создайте обычную закрытую ссылку с **IP-адресом** VDS и именем его
сертификата, например `--server https://203.0.113.10 --sni vpn.example.org`
через `foxtunnel share`. Адрес документационный: замените его реальным.
Полученный файл ссылки хранится 0600; секрет не помещайте в командную строку.
Выбранный транспорт сохраняется; H3 по умолчанию использует Go QUIC.

`/etc/foxtunnel/vpn-client.json`:

```json
{
  "v": 1,
  "interface": "ftvpn0",
  "underlay": "eth0",
  "gateway": "192.168.1.1",
  "ipv4": "100.96.0.2",
  "ipv6": "fd62:666f:78::2",
  "dns4": "9.9.9.9",
  "dns6": "2620:fe::fe"
}
```

Gateway — ваш действующий шлюз на underlay, той же семьи, что IP сервера. IPv4/IPv6
пользователя должны совпадать с сервером. DNS — явные публичные адреса, доступные
с выхода; приведённые значения — пример конфигурации, не рейтинг резолверов.

```sh
foxtunnel vpn-client --config /etc/foxtunnel/vpn-client.json \
  --link-file /etc/foxtunnel/connection.txt
# Для частного CA дополнительно: --ca-cert /etc/foxtunnel/root.pem
```

Порядок: проверка конфигурации/коллизий → атомарная блокирующая nft-таблица → TUN →
host route к серверу через исходный шлюз → DNS через resolvectl → split defaults
IPv4 и IPv6 через TUN → проверенный TLS → IP-сессия. Никакого отключения проверки
сертификатов. Во время ошибки установки direct egress также остаётся закрытым.

Клиентская таблица `inet foxtunnel_vpn_client` разрешает loopback, TUN и только
TCP/UDP к точному endpoint/порту с UID процесса на underlay. IPv6 neighbor discovery
с hoplimit 255 разрешён отдельно; DNS/DHCP/прочие данные в underlay не разрешены.
Чужие defaults не заменяются: добавляются /1 маршруты; endpoint исключён /32 или
/128. Занятые интерфейсы, таблица и существующий exact host route отклоняются.

## Отказы и отключение

При обрыве поток закрывается без IP replay; клиент повторяет **только установку**
сессии с паузой 1–10 с. Никакого выхода через обычную сеть. После паузы процесса
и возврата того же underlay соединение может восстановиться. Адреса/шлюз заданы
явно: переход на другой Wi-Fi/шлюз требует новой настройки; до неё выход блокируется.
Сохранение уже существующих TCP-соединений через полный перезапуск не гарантируется.

При SIGTERM, SIGKILL, аварии, ошибке CA или недоступном сервере kill switch
**не удаляется**. TUN FD закроется, defaults TUN исчезнут, но прямые IPv4/IPv6/DNS
останутся заблокированными. После аварии сначала выполните явное отключение,
затем заново запустите клиент. Обновление/перезапуск без окна явного disconnect
в этой версии не реализованы.

```sh
# Только если вы осознанно хотите вернуть обычную сеть:
foxtunnel vpn-down --config /etc/foxtunnel/vpn-client.json \
  --link-file /etc/foxtunnel/connection.txt
```

Команда проверяет наличие нашей таблицы, снимает DNS link policy, TUN и точный
endpoint route, затем удаляет только `foxtunnel_vpn_client`. Она разрешает direct
egress намеренно. Исходные DNS/defaults других интерфейсов сохранялись.
Для удаления серверной политики сначала остановите IP-сервис, затем:
`foxtunnel vpn-network --config /etc/foxtunnel/vpn-server.json --remove`.

Kill switch действует в текущем network namespace. Он не защищает процессы,
намеренно запускаемые администратором в другом namespace, и не переживает reboot
без отдельной ранней загрузки политики. Код не меняет boot/systemd-конфигурацию.

## Протокол, учёт и границы

- Явная согласованная `X-FoxTunnel-Network: ip-v1`, authority
  `ip.foxtunnel.invalid:1`; старый/неподготовленный сервер отклоняет режим.
  Для обычного TCP этот authority не включает IP. Сжатие/переход на plaintext отсутствуют.
- Каждая запись: big-endian uint16 length + полный IP-пакет, 20–1280 байт.
  Неизвестная версия IP, длина, IPv4 checksum/options, IPv6 routing/options и
  неподдерживаемый протокол отклоняются; разрешены TCP, UDP, ICMP и обычные фрагменты.
- Сервер проверяет фиксированный source адрес пользователя, публичный destination
  и обратный destination до передачи ядру/клиенту. `--allow-private` явно ослабляет
  только адресную политику назначения; изоляция host/peers nftables сохраняется.
- `quota_bytes` учитывает IP envelope, **включая IP/transport headers и реальные
  TCP retransmissions**, в обоих направлениях; framing/TLS/HTTP не учитываются.
  Это отличается от payload-учёта обычного TCP/bond, но использует тот же журнал
  пользователя. Пакет списывается целиком до injection/delivery; остаток меньше
  пакета означает закрытие, без частичной отправки.
- `max_tunnels` считает одну IP-сессию, не каждый вложенный TCP/UDP flow. Kernel
  conntrack/NAT имеет собственные системные пределы. Нет неограниченных Go-очередей:
  два packet pumps и фиксированные буферы; backpressure обеспечивают stream/TUN.
- Это первый Linux-режим, не Android/macOS/Windows VPN, не RFC CONNECT-IP и не
  перенос существующего выходного TCP-сокета. Мобильный roaming, DHCP renewal,
  boot-time firewall и длительные/platform испытания остаются дальнейшей работой.

SDK: `Client.DialIP(ctx)` возвращает `IPConn` с `ReadPacket`/`WritePacket`, `IPMTU`
и обычным `Close`; Client.Close владеет этими соединениями. Контекст управляет
установкой. `ServerConfig.IPHandler` — явный managed handler для хоста, который
сам управляет TUN/firewall; обычный NewServer не меняет ОС.

Проверки: wire/parser fuzz, отказ IP negotiation, IPv4/IPv6 на семи transport modes,
NSS и opt-in Neqo, metering и отзыв. Отдельный root-CI создаёт три изолированных
netns и настоящие TUN/NAT/nft: TCP/UDP, DNS, IPv6, freeze/resume, link loss/recovery,
SIGKILL и отсутствие direct egress; после явного vpn-down проверяет его возврат.
Тестовый DNS использует private netns resolv.conf; боевой systemd-resolved отдельно
требует эксплуатационной проверки на целевой машине.
