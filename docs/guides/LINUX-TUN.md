# Linux TUN для FoxTunnel — экспериментальный этап 3

**Русский** · [English](LINUX-TUN.en.md) · [Документация](../README.md)

Это интеграция с **внешним sing-box 1.14+**, использующая локальный SOCKS5 FoxTunnel. Нативный TUN и собственный TCP/IP-стек пока не реализованы. Создание конфигурации не меняет сеть и не требует root.

## Сделано 5 из 7 задач (код, без полевой проверки)

- [x] Генератор sing-box TUN для Linux
- [x] Подключение TCP/UDP к локальному SOCKS5 FoxTunnel; UDP v2 экспериментален
- [x] IPv4/IPv6 маршруты и точечные исключения IP серверов FoxTunnel
- [x] Перехват DNS на TUN и числовой upstream через SOCKS5
- [x] nftables-guard с DROP по умолчанию, остающийся при аварии процесса; офлайн-тесты
- [ ] Сетевые испытания в отдельном namespace: TCP, UDP, DNS, IPv6, падение сервера и утечки
- [ ] Нативный TUN без внешнего sing-box

**5/7 — число реализованных компонентов, а не доказательство их работы в сети.**

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

**Предупреждение:** run.sh включает правила DROP **до** старта sing-box и может оборвать Интернет, SSH, LAN и обновления. Разрешены loopback, TUN и конкретный IP/порт сервера на физическом интерфейсе. При аварии sing-box guard остаётся, но после перезагрузки правила могут пропасть. Не применяйте режим на production.

На Linux локальный DNS-stub 127.0.0.53 может не перехватываться TUN; внешний DNS тогда должен блокироваться guard, но нужна отдельная проверка. Другие network namespace, привилегированные изменения правил, DoH и смена сети требуют испытаний.

~~~sh
python3 -m unittest discover -s scripts -p test_linux_tun_companion.py -v
~~~

Это офлайн-тесты генератора, **не** тест настоящего TUN. См. [sing-box TUN](https://sing-box.sagernet.org/configuration/inbound/tun/) и [SOCKS outbound](https://sing-box.sagernet.org/configuration/outbound/socks/).
