# Linux TUN для FoxTunnel — экспериментальный этап 3

**Русский** · [English](LINUX-TUN.en.md) · [Документация](../README.md)

Это интеграция с **внешним sing-box 1.14+**, использующая локальный SOCKS5 FoxTunnel. Нативный TUN и собственный TCP/IP-стек пока не реализованы. Создание конфигурации не меняет сеть и не требует root.

## Сделано 6 из 7 задач (код и изолированный Linux CI)

- [x] Генератор sing-box TUN для Linux
- [x] Подключение TCP/UDP к локальному SOCKS5 FoxTunnel; UDP v2 экспериментален
- [x] IPv4/IPv6 маршруты и точечные исключения IP серверов FoxTunnel
- [x] Перехват DNS на TUN и числовой upstream через SOCKS5
- [x] nftables-guard с DROP по умолчанию, остающийся при аварии процесса; офлайн-тесты
- [x] Изолированный Linux стенд: **полный сквозной путь приложения → sing-box TUN → SOCKS5 FoxTunnel → TLS 1.3 → выходной сервер**, TCP IPv4/IPv6, UDP v2, DNS через туннель, блокировка прямого трафика после остановки FoxTunnel и sing-box, потеря/возврат физического интерфейса. **Это не полный аудит утечек на реальных устройствах.**
- [ ] Нативный TUN без внешнего sing-box

**6/7 — шесть задач реализованы и профильный CI-стенд пройден.** При этом полноценная защита от утечек во всех ОС и сетевых сценариях не доказана.

## Генерация

Требования: Linux, Python 3.11+, sing-box 1.14+ и nftables. Нужен доступ к **локальной консоли**; не запускайте firewall на VPS по SSH.

Настройте FoxTunnel SOCKS5 на 127.0.0.1:1080. Серверный HTTPS URL FoxTunnel должен содержать **числовой IP**, а имя TLS-сертификата проверяться отдельно через флаг SNI: иначе до запуска туннеля потребуется прямой DNS-запрос. Укажите все IP резервных входов.

~~~sh
python3 scripts/linux_tun_companion.py \
  --endpoint 198.51.100.42:443 \
  --uplink enp3s0 --tun ftun0 \
  --socks-port 1080 --dns 1.1.1.1 \
  --carrier tcp --out /tmp/foxtunnel-tun-lab
~~~

Адрес 198.51.100.42 — **пример из диапазона для документации**; замените адресом вашего реального сервера. Для HTTP/3 используйте --carrier udp. Скрипт создаёт новую приватную папку с sing-box.json, killswitch.nft, run.sh и README.txt.

Проверка, запуск и отключение:

~~~sh
sing-box check -c /tmp/foxtunnel-tun-lab/sing-box.json
sudo nft -c -f /tmp/foxtunnel-tun-lab/killswitch.nft
sudo /tmp/foxtunnel-tun-lab/run.sh
# После остановки программ, с ЛОКАЛЬНОЙ консоли:
sudo nft delete table inet foxtunnel_tun_guard
~~~

**Предупреждение:** run.sh включает правила DROP **до** старта sing-box; внутри netfilter защитная цепочка имеет приоритет `filter` (после `auto_redirect` sing-box), иначе перенаправляемый трафик был бы ошибочно заблокирован и может оборвать Интернет, SSH, LAN и обновления. Разрешены loopback, TUN и конкретный IP/порт сервера на физическом интерфейсе. При аварии sing-box guard остаётся, но после перезагрузки правила могут пропасть. Не применяйте режим на production.

На Linux локальный DNS-stub 127.0.0.53 может не перехватываться TUN; внешний DNS тогда должен блокироваться guard, но нужна отдельная проверка. Другие network namespace, привилегированные изменения правил, DoH и смена сети требуют испытаний.

~~~sh
python3 -m unittest discover -s scripts -p test_linux_tun_companion.py -v
~~~

Это офлайн-тесты генератора, **не** тест настоящего TUN. См. [sing-box TUN](https://sing-box.sagernet.org/configuration/inbound/tun/) и [SOCKS outbound](https://sing-box.sagernet.org/configuration/outbound/socks/).

## Сетевой стенд (проверка только nft guard)

В GitHub Actions используется `scripts/test_linux_tun_netns.py`: две новые изолированные сетевые namespace, соединённые veth без доступа в Интернет. Стенд проверяет разрешённый HTTPS TCP к указанным IPv4/IPv6 адресам, запрет других портов и прямого UDP/DNS, переключение разрешённого транспорта на UDP и сохранение policy DROP при остановке имитатора сервера. Для IPv6 guard разрешает только NDP (Neighbor Solicitation/Advertisement с hop limit 255) на выбранном uplink — иначе даже разрешённое IPv6-соединение не установится.

Запуск вручную только на отдельной Linux машине с root, iproute2 и nftables:

~~~sh
sudo -E env FOXTUNNEL_TUN_NETNS=1 python3 -m unittest discover -s scripts -p test_linux_tun_netns.py -v
~~~

**Первый стенд проверяет только nftables. Второй стенд действительно проверяет sing-box TUN и сквозной FoxTunnel TLS 1.3.** В текущем окружении тесты могут пропускаться без явного включения. Итоговый статус см. [workflow](https://github.com/SawaMEN/FoxTunnel/actions/workflows/tun-netns.yml).

## Полный изолированный стенд FoxTunnel и sing-box

Сквозной стенд [Linux TUN end-to-end CI](https://github.com/SawaMEN/FoxTunnel/actions/workflows/tun-e2e.yml) собирает текущий FoxTunnel из исходников, проверяет SHA-256 tar.gz sing-box **1.14.1**, создаёт два изолированных Linux network namespace и запускает настоящий TUN и авторизованный FoxTunnel TLS 1.3. Проверяются TCP IPv4/IPv6, UDP-поток v2, DNS-перехват до локального тестового DNS, запрет прямого выхода после остановки клиента и sing-box, а также отключение/возврат физического интерфейса. Для теста используются зарезервированные адреса 198.18.0.0/15, тестовый сертификат и тестовые данные; Интернет и firewall основного namespace не меняются.

**Статус: 6/7.** Единственная оставшаяся задача в этом плане — нативный TUN + TCP/IP стек без внешнего sing-box. Проверки production-утечек, многосетевого failover, IPv6 DNS системного резолвера и полевые испытания остаются отдельными работами по качеству и безопасности.
