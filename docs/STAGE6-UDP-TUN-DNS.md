# Этап 6 — UDP, TUN, DNS, IPv4/IPv6 (исторический стенд)

**Лабораторная проверка завершена: 5/5 (100%)**, но встроенный
Linux TUN и VPN-launcher **не входят в текущий продукт FoxTunnel**.

## Почему исходники TUN не восстановлены в `main`

FoxTunnel — независимое ядро HTTPS-протокола для встраивания в VPN-клиенты
и серверные панели. В [контракте интеграции](INTEGRATION.md) обязанности
разделены:

- **Hiddify-app** управляет Android VpnService / Apple NetworkExtension,
  TUN/packet adapter, DNS, IPv4/IPv6, маршрутами, kill-switch и reconnect.
  FoxTunnel предоставляет HTTPS-туннель, клиентские TCP-соединения,
  опциональный UDP relay и SOCKS/Go API. Старый Linux TUN не заменяет
  Android/macOS VPN-драйверы и не нужен в релизе протокола.
- **3x-ui** запускает FoxTunnel как отдельный HTTPS-сервер и управляет
  конфигурацией, пользователями, сертификатами и жизненным циклом.
  TUN, routing policy и VPN-launcher серверной панели не требуются.

Поэтому исторический `internal/nativetun/`, `linux_native_vpn.py`,
sing-box companion, root-only netns tests/workflows и их gVisor/tun2socks
зависимости **не восстанавливаются в основном дереве и релизах**.
Подобные функции должны жить в хост-приложении, а не в протокольном ядре.

## Проверенные исторические результаты

Работа была завершена до удаления экспериментальной обвязки:

1. Отмена зависших SOCKS5 TCP CONNECT и UDP ASSOCIATE handshakes,
   изолированная DNS/nftables политика IPv4 и IPv6.
2. Повторные native TUN TCP/UDP/DNS A и AAAA E2E-тесты в Linux netns.
3. Отказ от некорректных UDP пакетов/кадров, ограничение UDP-сессий,
   проверка spoofed reply IP/port, конкурентного доступа и лимитов.
4. Сохранение независимого nftables guard при SIGKILL клиента,
   физическом link flap, остановке/перезапуске exit, проверка
   восстановления новых TCP/UDP/DNS соединений.
5. Два Linux netns soak-прогона по 25 секунд, **186/186 успешных
   TCP/UDP/DNS probes** в каждом, с измерениями RSS/FD/socket FD
   и 34-секундным периодом освобождения ресурсов. Обычные UDP
   mapping idle: 30 секунд; DNS mapping idle: 3 секунды.

- [Успешный native TUN CI](https://github.com/SawaMEN/FoxTunnel/actions/runs/39448375868)
- [Go/race-тесты](https://github.com/SawaMEN/FoxTunnel/actions/runs/39448376040)
- [Исторический коммит со всеми исходниками и тестами](https://github.com/SawaMEN/FoxTunnel/tree/5229cf304645d20cad62bb32a2c197f93a4f3c4e)

**Важно:** эти тесты относятся к старой Linux TUN реализации.
Они не сертифицируют нынешнее protocol-core, Android/macOS Hiddify
или интеграцию 3x-ui; они не подтверждают безопасность при реальных
сетевых ограничениях, полное отсутствие DNS leaks на устройстве,
криптографическую UDP anti-replay или отсутствие медленных утечек.
Отдельное интеграционное тестирование Hiddify и 3x-ui остаётся необходимым.
