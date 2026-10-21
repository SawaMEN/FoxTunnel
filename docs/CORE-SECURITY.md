# Безопасность protocol-core: этап 5 из 10

Состояние: собственная ревизия и автоматические регрессии. Независимый
security review ещё не предоставлен. Наличие зелёного CI не закрывает этот критерий.
Runtime-ревизия: `9c59aad62153ea9e063a29712b68eaaff99e9cb1`,
[PR #40](https://github.com/SawaMEN/FoxTunnel/pull/40).
Ссылки на успешные Go/NSS/Neqo проверки находятся в
[плане реализации](IMPLEMENTATION-PLAN.md).

## Проверяемые границы

| Граница | Проверяемый контракт | Подтверждение |
|---|---|---|
| Клиент → TLS endpoint | CA и hostname обязательны; SPKI добавляется к ним; ошибка доверия не вызывает downgrade или передачу credentials | identity/native-verification тесты Go/NSS; Neqo TrustBeforeCredentials; внешний SDK |
| Один пользователь → другой | Общие carrier-сессии привязаны к владельцу; отзыв не закрывает соединение другого пользователя | AccessRevocationIsolation, Bond owner, новые ManagedUDPIsolation |
| Ротация → активные UDP-сессии | Старый поток закрывается, старый пароль отвергается, новый принимается; учёт байтов сохраняется | ManagedUDPIsolation: rotate/disable/remove на H2/H3, Go/NSS/Neqo |
| Авторизованный клиент → выходная сеть | TCP/UDP фильтруют числовые IP; DNS проверяется перед socket dial; повторная попытка TCP использует закреплённый IP | SpecialDestinationsDeniedBeforeDial и DNSFilteredAndPinnedAcrossRetries |
| Авторизованный клиент → ресурсы | Общие admission-лимиты и квоты; чтение UDP-v1 входит в общий бюджет запроса | UDPBodyBudgetReleasesAdmission по H2/H3; существующие admission/quota/queue тесты |
| Неавторизованный клиент → cover | В cover не передаются Proxy-Authorization и X-FoxTunnel-*; секреты не попадают в диагностику | Stage2Cover, AccessDocumentsAndDiagnostics, profile secret-file tests |

## Исправления этой итерации

Фильтр назначений консервативен. Помимо private/loopback/link-local/multicast
он отклоняет IPv4 `0/8`, shared, documentation, benchmark, protocol-assignment,
старый 6to4 relay и reserved `240/4`. IPv4-mapped адрес сначала преобразуется
в IPv4 и проходит тот же фильтр. Scope/zone ID по умолчанию запрещён.

Для IPv6 по умолчанию допускается только `2000::/3`, за вычетом `2001::/23`,
`2001:db8::/32`, `2002::/16`, `3fff::/20`. Это сознательно строгая политика:
включает запрет некоторых специальных глобально достижимых сервисов.
NAT64, Teredo и 6to4 не допускаются, чтобы встроенный IPv4 не обходил фильтр.
Перечень требует ревизии при изменениях адресного пространства.

Основание классификации — реестры IANA, проверенные 21 октября 2026 года:
[IPv4 special-purpose](https://www.iana.org/assignments/iana-ipv4-special-registry/)
и [IPv6 special-purpose](https://www.iana.org/assignments/iana-ipv6-special-registry/).
Политика FoxTunnel строже признака Globally Reachable из этих реестров.

TCP разрешает имя один раз, отбрасывает запрещённые IP и передаёт dialer только
числовые адреса. Тест моделирует смешанный ответ, отказ первого public IP,
переход ко второму без повторного DNS и private-only ответ следующей операции.
UDP использует тот же IP-фильтр и закрепляет числовой IP в connected socket.

UDP-v1 теперь начинает общий бюджет `min(DialTimeout, 3s)` до чтения тела.
По истечении бюджета тело закрывается, чтение прерывается и admission-слот
освобождается. Раньше медленная загрузка тела могла удерживать слот без этого
таймаута. Проверка выполняется настоящими H2/H3 клиентами с незавершённым телом.

## Ограничения и review

- `AllowPrivate=true` явно отключает ограничения адресов назначения. Используйте
  его только там, где доступ к локальной сети задан политикой приложения-хоста.
- IP-фильтр не заменяет egress firewall: нестандартные маршруты, собственный
  NAT64-prefix внутри public allocation и доступные через public IP внутренние
  сервисы требуют сетевой политики оператора.
- Basic credentials остаются повторно используемыми до отзыва/ротации.
  Новый anti-replay протокол этой итерацией не вводится.
- TLS endpoint и защита конфигурации/state принадлежат процессу-хосту;
  protocol-core не создаёт системный sandbox или VPN-интерфейс.
- Проверки не доказывают устойчивость к DPI или идентичность Firefox.

Независимому reviewer передаются исходники и CI конкретной runtime-ревизии,
[wire contract](reference/WIRE-DRAFT-0.md),
[UDP lifecycle](UDP-H3.md), [TCP lifecycle](TCP-CORE.md),
`internal/access`, `internal/tlsidentity`, Go/NSS/Neqo transports,
WSS/XHTTP/Bond/cluster, парсеры профилей и CLI host boundary.
Отчёт должен назвать reviewer, ревизию, область и методы проверки, найденные
замечания с серьёзностью и состояние исправлений. Этап остаётся открытым
до получения такого отчёта без открытых critical/high.
