# Neqo: проверка совместимости и отказов

Методика/сборка: [RU](../../../research/NEQO-INTEGRATION.md) /
[EN](../../../research/NEQO-INTEGRATION.en.md).

Linux amd64, Go 1.26.9, Rust 1.99.1, Neqo 0.33.0
`1ec4c2a3ccd7ada264112d1b70b070381557d844`, nss-rs 0.16.1
`ba8a3f6acffc7e25749054969ccbbb3ca615df7f`, NSS 3.130 из hash-pinned Firefox
158.0. Сервер независимый: существующий Go/quic-go сервер и отдельные direct H3
фикстуры. Не Neqo ↔ Neqo и не запуск браузера Firefox.

`interop.txt` сохраняет три последовательных прогона выбранных сетевых тестов с
race detector. Это функциональные наблюдения, **не throughput benchmark**:

- 512 КиБ echo с reuse/cold handshake и без resumption; четыре параллельных upload.
- Настоящий SOCKS: разные данные на 2 МиБ, half-close и проверенный SPKI pin.
- Публичный SDK: H3 и NSS H2 fallback, pin, half-close и отмена setup-контекста.
- Неверные CA/SNI/pin и ALPN не допускают HTTP/авторизацию или H2 downgrade.
- Полный UDP blackhole держит порт открытым и отбрасывает Initial: проверяется
  handshake budget 150 мс и переключение на настоящий NSS H2. Быстрый ICMP отказ
  не подменяет этот тест.
- Partial-loss UDP proxy задерживает каждый пакет на 5 мс в каждом направлении и
  отбрасывает каждый 17-й datagram отдельно в обоих направлениях. Очередь proxy —
  64 пакета на направление. Теряются настоящие QUIC-пакеты; 256 КиБ echo должно
  совпасть побайтно. Счётчик включает реальный обмен/повторы, не только payload.

Один предварительный прогон этого partial-loss сценария с race detector:
622,6 мс, 43 отброшенных пакета, echo совпал. Число пакетов и время меняются при
планировании, congestion control, ACK/coalescing и повторной передаче. Три
сохранённых повторения являются основным журналом, а не обещанием этого времени.
Это userspace loopback; не `tc netem`, не независимые внешние маршруты/полоса,
не операторские ограничения и не сравнение с NaiveProxy/Firefox/DPI.

Команда после pinned build (вывод дополнительно содержит имя теста и версию Go):

```sh
source rust/neqo-bridge/target/foxtunnel-build/env.sh
go test -race -tags nss,neqo ./internal/neqo ./internal/tunnel . \
  -run 'TestNeqo|TestQUIC|TestPublicNeqo|TestRealQUIC|TestALPN|TestIndependentH3|TestConcurrentDuplex|TestTrustBefore|TestBlockedUDP|TestPeerReset|TestMalformed' \
  -v -count=3 -timeout=60s
```

Полные suite/vet и нативный workflow проверяются отдельно; лог здесь сфокусирован
на Neqo. Native-память NSS, длительная стабильность, другие ОС/arm64 и браузерный
отпечаток этим журналом не установлены.
