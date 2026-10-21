# Аудит main: цель — 200 подтверждённых ошибок

База первого пакета: `653c985c66f0594e270adfcafa05fcd7ac71a933`.
Подтверждены и исправлены **21 из запрошенных 200** разных дефектов.
Это промежуточный результат, не утверждение о завершении аудита или наличии
ровно 200 ошибок. Варианты входных данных и повторные проявления одной ошибки
отдельно не считаются. Замечания по стилю в счётчик не входят.

Каждый тест ниже воспроизводил проблему до исправления соответствующего
production-кода. Для новых processhost-сценариев изменён тестовый executable:
он создаёт отдельного дочернего владельца stdout, сам production-код при
подтверждении дефекта оставался исходным. Во всех случаях тесты проверяют
наблюдаемое поведение, а не только наличие новой проверки в реализации.

| ID | Дефект и последствие | Регрессионная проверка |
|---|---|---|
| 001 | Генератор рекламировал нестандартный порт URL, но слушал 443; TCP и H3 профили не подключались к сгенерированному серверу | `bootstrap.TestAuditSetupAdvertisedPort` |
| 002 | Join обходил проверку приватности файла подключения и принимал доступный другим пользователям пароль | `bootstrap.TestAuditJoinRejectsPublicSecretFile` |
| 003 | Join разрешал исходный credential-файл с произвольным именем внутри публичного web root | `bootstrap.TestAuditJoinCannotPublishOriginalSecret` |
| 004 | Генератор принимал обычный файл как web root и создавал неработоспособную конфигурацию | `bootstrap.TestAuditSetupRejectsNonDirectorySite` |
| 005 | AddNode не обновлял существующий узел при эквивалентном написании HTTPS origin; вместо замены получался отказ из-за дубликата | `bootstrap.TestAuditAddNodeReplacesEquivalentOrigin` |
| 006 | UDP frame с полным заголовком длины и отсутствующим телом возвращал обычный EOF, маскируя усечение | `udpproto.TestAuditDeclaredFrameWithoutBodyIsTruncated` |
| 007 | Fallback принимал тот же endpoint повторно через написание порта 0443 и обходил проверку уникальности | `tunnel.TestAuditFallbackRejectsPortAliases` |
| 008 | Импортируемый профиль принимал пустой порт, который затем отвергал SDK | `profile.TestAuditLinkRejectsEmptyPort` |
| 009 | Сброс качества после смены сети сохранял вычисленные скорости предыдущей сети | `nodeperf.TestAuditNetworkChangeInvalidatesOldRates` |
| 010 | Файл пинов отвергал эквивалентное написание origin с неявным/явным портом 443 | `tunnel.TestAuditPinsMatchEquivalentOrigin` |
| 011 | HTTP cover открывал FIFO до проверки типа файла и мог навсегда занять обработчик | `tunnel.TestAuditCoverRefusesFIFOBeforeOpening` (Linux) |
| 012 | После обязательных per-node SPKI pins можно было добавить непроверенный fallback; новый адрес использовал транспорт без пина | `tunnel.TestAuditPinnedClientRejectsFallbackReconfiguration` |
| 013 | UTF-8 username проходил encode/decode профиля и создание клиента, но отвергался серверным Basic parser | `authheader.TestAuditUTF8UsernameAcceptedByWireParser`, `tunnel.TestAuditUTF8CredentialsTransferOverH2` |
| 014 | Профиль и конструкторы принимали credentials за пределами wire-лимитов или с недопустимым username; такие подключения заведомо не могли пройти авторизацию | `profile.TestAuditLinkRejectsUnusableUsername`, `tunnel.TestAuditClientRejectsUnusableCredentials` |
| 015 | Таймаут проверки версии не ограничивал чтение stdout, унаследованного потомком уже завершившегося процесса | `processhost.TestAuditVersionChildCannotRetainStartupPipe` |
| 016 | После kill основного процесса унаследованный stdout мог удерживать Close сверх пятисекундного бюджета | `processhost.TestAuditShutdownClosesDescendantHeldOutput` |
| 017 | Уже отменённый DialContext сначала создавал запрос с новым фоновым lifetime и мог обратиться к транспорту до асинхронной отмены | `tunnel.TestAuditCancelledDialNeverStartsTransport` |
| 018 | Запрет публикации версии v0.0.0-ci применялся к release request, но обходился публикацией tag с этим именем | `ReleaseRequest.test_audit_ci_tag_cannot_publish` |
| 019 | Smart Bond принимал эквивалентное написание адреса координатора за relay, отвергал допустимую topology или применял relay tax к прямому маршруту | `tunnel.TestAuditSmartBondRecognizesCoordinatorAliases` |
| 020 | Bond принимал EOF вместо ACK для upload/FIN/close и молча отбрасывал payload в EOF/ACK; некорректный ответ выдавался за успех | `bond.TestAuditRejectsMalformedSuccessRecords` |
| 021 | При alias основного HTTPS origin из discovery (например, ведущий ноль в порте) primary SPKI/SNI policy не наследовалась; действительная CA позволяла обойти обязательный pin | `tunnel.TestAuditPrimaryPinAppliesToDiscoveredOriginAlias` (реальный HTTPS/H2) |

Исправление 012 дополнительно закрывает request body и отказывает неизвестному
origin в identity pool с обязательными per-node pins. Конфигурация fallback
фиксируется до установки пинов. Включение dynamic discovery после статических
per-node pins также отвергается до I/O (`TestAuditPinnedClientRejectsDynamicDiscoveryBeforeIO`). Изменения TLS backend/profile сохраняют pins.

Единая функция проверки credentials сохраняет UTF-8 имена статических
профилей и произвольные байты пароля в wire-парсере, ограничивает длины и
отвергает whitespace/control/colon в username. Отдельная политика managed
accounts с ASCII username не расширяется.

## Проверки первого пакета

- Полный `go test -race ./... -count=1 -timeout=180s` прошёл.
- Все новые core-регрессии повторены пять раз с race detector.
- Processhost проверяет реальные дочерние процессы и удержанные stdout pipes.
- `go vet`, core boundaries, Markdown links и `git diff --check` прошли.
- Полный Python-набор: 160 тестов, два штатно пропущены, ошибок нет.

NSS/Neqo и платформенные результаты CI фиксируются отдельно после выполнения;
наличие локального PASS не выдаётся за native CI или независимый security review.

## Проверки дополнения 019

- Полный Go race-набор и `go vet ./...` повторно прошли после изменения.
- Для первого коммита пакета все 17 PR workflows завершились успешно, включая native platform operations, NSS и Neqo.

## Проверки дополнения 020

Пять вариантов некорректного ответа воспроизведены до исправления; полный Bond-набор и полный Go-набор с race detector, `go vet`, Markdown links и core boundaries прошли после исправления.

## Проверки дополнения 021

Реальный HTTPS/H2 тест сначала воспроизвёл обход неправильного primary pin через alias порта; после исправления оба написания отвергают неправильный pin, а правильный pin разрешает alias. TLS/discovery регрессии повторены пять раз с race detector. Полный Go race-набор, `go vet`, core boundaries, Markdown links и diff check прошли.
