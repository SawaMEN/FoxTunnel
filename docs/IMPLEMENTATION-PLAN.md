# План реализации FoxTunnel — 10 этапов

Актуальный план независимого protocol-core. Этапы 1–7 включены в main 21 октября
2026 года через [PR #43](https://github.com/SawaMEN/FoxTunnel/pull/43), merge `3292c9ac`.
Открытые критерии защиты main и независимого аудита при этом не закрываются.
Цель: совместимое ядро для Hiddify-app и 3x-ui, без зависимости от sing-box/Xray.
TUN, маршруты, системный DNS и VPN-интерфейс принадлежат приложению-хосту.

Счётчик показывает выполненные задачи, а не процент production-готовности.
Этап считается завершённым после выполнения всех его критериев и успешных
проверок. Старые STAGE-документы и [план из 8 этапов](ROADMAP-LAB-ONLY.md)
содержат исторические результаты; их номера не являются номерами этого плана.
Локальные стенды и CI достаточны для лабораторных задач. Полевые измерения
нужны для соответствующих утверждений о реальных сетях, а не для каждого этапа.

## Этап 1 из 10 — очистка и стабилизация структуры

**Выполнено 4 из 5 задач.** Этап открыт до включения защиты ветки.
Полная CI-матрица изменений проверяется в [PR #36](https://github.com/SawaMEN/FoxTunnel/pull/36).
База ревизии: `97036bf8dafddff7c46497c91488a87222132b05`.

- [x] Ревизия `cmd/`, `internal/`, `experiments/`, `scripts/`.
  В дереве нет встроенного TUN, VPN-launcher и старых root-only netns workflows.
  В ядре сохраняются сервер, клиентский SOCKS-адаптер, SDK и транспорты.
- [x] Актуализировать документацию и CI после удаления TUN.
  Устаревшая лабораторная карта помечена как историческая; профильные
  security/UDP/fastpath/cover/node/fingerprint проверки переведены на `main`.
  Условия публикации экспериментального Mozilla-релиза остаются в его
  отдельном workflow с проверкой одноразового запроса версии.
- [x] Зафиксировать границы исследований и runtime.
  Добавлен `experiments/README.md` и проверка транзитивных зависимостей SDK/CLI
  для обычной, NSS и Neqo сборок. Native runtime bridge остаётся в `rust/`.
- [x] Подтвердить отсутствие лишних зависимостей.
  CI выполняет `go mod tidy -diff` в корне и внешнем SDK-модуле;
  проверка границ запрещает TUN/sing-box/Xray-модули. Удалять текущие зависимости
  без результата Go resolver нельзя. Обе проверки tidy и проверка границ
  обычной сборки прошли на коммите `60f7b51e` в
  [Tests CI](https://github.com/SawaMEN/FoxTunnel/actions/runs/39469093745).
  Изменять go.mod/go.sum по результату проверки не потребовалось.
- [ ] Защитить `main` обязательными проверками.
  Нужна применённая настройка GitHub: pull request перед слиянием,
  обязательный `go` из workflow `Tests`, запрет force-push и удаления.
  Наличие YAML не означает наличие защиты ветки; доступный GitHub-коннектор
  не предоставляет изменение административных настроек.

Проверки этого цикла: `Tests`, NSS и Neqo CI, текущие интеграционные workflow.
Изменение протокола и удаление экспериментальных транспортов в этап 1 не входят.

## Этап 2 из 10 — спецификация и совместимость

**Выполнено 5 из 5 задач.** Результаты в [PR #37](https://github.com/SawaMEN/FoxTunnel/pull/37),
построенном поверх PR #36; изменения включены в main через PR #43.

- [x] Завершить спецификацию TCP и UDP: форматы, размеры, EOF/half-close,
  H2/H3 POST, одноразовый UDP-v1 и потоковый UDP-v2.
- [x] Реализовать согласование версии и возможностей: строгая opt-in политика
  SDK, отказ от несовместимых версий/возможностей, сохранение legacy по умолчанию.
- [x] Зафиксировать авторизацию, ошибки и отсутствие автоматического downgrade.
- [x] Добавить фиксированные тестовые векторы и граничные проверки кодеков.
- [x] Проверить матрицу strict/legacy/future, все основные транспорты,
  внешний SDK и стандартный HTTP/2 peer без внутреннего клиентского кода.

Спецификация: [wire draft 0](reference/WIRE-DRAFT-0.md),
[согласование версии](reference/WIRE-NEGOTIATION.md).
Подтверждение:

- [Tests: race, fuzz, векторы, внешний HTTP/2 peer](https://github.com/SawaMEN/FoxTunnel/actions/runs/39473024445).
- [NSS](https://github.com/SawaMEN/FoxTunnel/actions/runs/39473024513).
- [Фактическая совместимость предыдущего ядра](https://github.com/SawaMEN/FoxTunnel/actions/runs/39473033834):
  CI собирает CLI из коммита `97036bf8dafddff7c46497c91488a87222132b05`,
  проверяет старый клиент/новый сервер и новый клиент/старый сервер,
  а также отказы строгой политики в обе стороны.
- [Внешний SDK на Linux, macOS и Windows](https://github.com/SawaMEN/FoxTunnel/actions/runs/39472368769).

Межверсионный стенд проверяет основной TCP/H2 контракт. Старые опубликованные
архивы, полный набор UDP/экспериментальных расширений между всеми тегами
и независимая реализация на другом языке отдельно не сертифицированы.
Новые несовместимые wire-версии пока не реализованы; future-version fixtures
проверяют корректный отказ, а не реальную реализацию draft-1.
Строгий режим включается через Go API; изменение CLI/профилей относится к интеграционному этапу.

## Этап 3 из 10 — стабильное TCP-ядро

**Выполнено 5 из 5 задач.** Изменения в [PR #38](https://github.com/SawaMEN/FoxTunnel/pull/38),
построенном поверх PR #37; изменения включены в main через PR #43.

- [x] Подтвердить основной H2 CONNECT: сброс после частичного ответа
  должен оставаться ошибкой, а не превращаться в успешный EOF.
- [x] Подтвердить H2 POST и WebSocket с Go/NSS, padding и без него,
  через прямой Go dial и локальный SOCKS.
- [x] Сохранить XHTTP явно экспериментальным; основной контракт остаётся
  TCP/H2, без утверждений о полной совместимости с Xray.
- [x] Проверить отмену, CloseWrite/ответ, backpressure и сброс таймаутов;
  закрытие должно разблокировать запись и освобождать резерв подключения.
- [x] Подтвердить отсутствие replay после частичной отправки/ответа,
  HTTP-отказа и response-plus-error; исправить порядок очистки setup.

Подтверждение:

- [Повторная TCP-матрица Go/NSS](https://github.com/SawaMEN/FoxTunnel/actions/runs/39488143428):
  новые регрессии и публичный SOCKS API повторены по пять раз;
  half-close, отмена, параллельная нагрузка и carrier-тесты — по три раза.
- [Полный NSS/race/vet набор](https://github.com/SawaMEN/FoxTunnel/actions/runs/39488135130).
- [Совместимость предыдущего ядра после исправления форматирования](https://github.com/SawaMEN/FoxTunnel/actions/runs/39488315562).
- [Окончательный Tests: race, fuzz, SDK, сборка, govulncheck](https://github.com/SawaMEN/FoxTunnel/actions/runs/39488306495).
- [Neqo: native/FFI/race проверки](https://github.com/SawaMEN/FoxTunnel/actions/runs/39488135094).

Повторная матрица и NSS/Neqo прошли на runtime-ревизии `4e77a155`;
окончательный Go набор и совместимость — на `aca3eeed`, отличающемся только
пустой строкой gofmt. Следующий коммит фиксирует документацию прогресса.

[Контракт TCP и проверяемые ограничения](TCP-CORE.md).
Независимое закрытие download-направления с продолжением upload в текущем
net/http сервере не обещается; поддерживаемый half-close — CloseWrite клиента
с сохранением ответа. Это ограничение записано, а не считается исправленным.

## Этап 4 из 10 — UDP и HTTP/3

**Выполнено 5 из 5 задач.** Изменения в [PR #39](https://github.com/SawaMEN/FoxTunnel/pull/39),
построенном поверх PR #38; изменения включены в main через PR #43.

- [x] Добавить общий Go API датаграмм: ExchangeUDP и OpenUDP/Send/Receive/Close,
  управление временем жизни, opt-in и общий лимит TCP/UDP/ожидающих операций.
- [x] Ограничить setup/завершение UDP: отмена UDP-v1, UDP-stream timeout,
  очистка при отказе, сброс повреждённого framing, ограниченные очереди.
- [x] Проверить IPv4/IPv6, удалённый DNS, пустые и предельные датаграммы,
  запрет oversize, стабильность UDP-сокета и потери без replay.
- [x] Проверить HTTP/3 после смены сети: новая QUIC-генерация и новая сессия,
  сохранение старой при возврате её пути, освобождение старого пула.
- [x] Подтвердить повторную Go/NSS/Neqo матрицу и внешний SDK на трёх ОС.

Локально прошли полный Go/race набор, внешний SDK и пятикратные Stage4 проверки.
Подтверждение runtime-ревизии `4d598879`:

- [Повторная UDP/H3 матрица Go/NSS](https://github.com/SawaMEN/FoxTunnel/actions/runs/39491631669):
  Stage4/race по пять раз и внешний UDP SDK по три раза.
- [Neqo: полный native/race набор и UDP-матрица по три раза](https://github.com/SawaMEN/FoxTunnel/actions/runs/39491632269).
- [Внешний SDK на Linux, macOS и Windows](https://github.com/SawaMEN/FoxTunnel/actions/runs/39491631553).
- [Полный Go набор](https://github.com/SawaMEN/FoxTunnel/actions/runs/39491631952) и
  [полный NSS набор](https://github.com/SawaMEN/FoxTunnel/actions/runs/39491631824).

Следующий коммит фиксирует только документацию прогресса.

[UDP API, ограничения и сценарии H3](UDP-H3.md).
Потери/задержки моделируются локально; произвольные NAT, Internet MTU и
мобильные сети этими результатами не сертифицированы.

## Этап 5 из 10 — безопасность

**Выполнено 4 из 5 задач.** Изменения в [PR #40](https://github.com/SawaMEN/FoxTunnel/pull/40),
построенном поверх PR #39; изменения включены в main через PR #43.
Независимый review ещё не предоставлен.

- [x] Проверить TLS/SNI/SPKI и запрет передачи credentials до проверки доверия.
- [x] Проверить изоляцию пользователей, ротацию/отзыв и сохранение учёта квот.
- [x] Усилить SSRF-фильтр TCP/UDP и подтвердить pin DNS без повторного разрешения.
- [x] Ограничить незавершённые UDP-запросы и проверить admission/очистку/race.
- [ ] Получить независимый security review без открытых critical/high замечаний.

Подтверждение runtime-ревизии `9c59aad6`:

- [Security/race регрессии Go](https://github.com/SawaMEN/FoxTunnel/actions/runs/39494115112):
  новые тесты и существующие TLS/изоляция/квоты по три раза; access/auth/TLS по пять раз.
- [NSS: полный race/vet/govulncheck и повторные security-тесты](https://github.com/SawaMEN/FoxTunnel/actions/runs/39494115198).
- [Neqo: полный native/race набор и отзыв UDP по три раза](https://github.com/SawaMEN/FoxTunnel/actions/runs/39494115150).
- [Полный Go набор](https://github.com/SawaMEN/FoxTunnel/actions/runs/39494115233) и
  [внешний SDK на трёх ОС](https://github.com/SawaMEN/FoxTunnel/actions/runs/39494115024).

Локально прошли полный Go/race набор, внешний SDK, go vet и повторные security-тесты.
Следующий коммит меняет только документацию прогресса.

[Контракты, исправления и пакет для review](CORE-SECURITY.md).
CI и собственная ревизия не заменяют независимый review. Его результат должен
быть приложен отдельно с ревизией кода, областью проверки и статусом замечаний.

## Этап 6 из 10 — NSS и Neqo

**Выполнено 5 из 5 задач.** Pins/FFI/ресурсы — [PR #41](https://github.com/SawaMEN/FoxTunnel/pull/41),
свежие wire-измерения — [PR #42](https://github.com/SawaMEN/FoxTunnel/pull/42); изменения включены в main через PR #43.

- [x] Подтвердить согласованность compiler/Cargo/Go API/runtime pins и отказ при дрейфе.
- [x] Проверить FFI lifecycle: повторные engine teardown, отмена, borrowed buffers и cgo pointers.
- [x] Получить воспроизводимую CPU/RSS/скорость/alloc матрицу Go-H2/NSS-H2/Go-H3/Neqo-H3 на одном runner.
- [x] Получить сопоставимые свежие Firefox/NaiveProxy/FoxTunnel TLS/H2 захваты начала соединения с версиями и происхождением.
- [x] Получить endpoint-decoded QUIC/H3 измерения трёх реализаций в общем стенде начала соединения (методы приложений различаются).

Подтверждение runtime-ревизии `b6d33368`:

- [Neqo CI: native/ABI/clippy/race и вся ресурсная матрица](https://github.com/SawaMEN/FoxTunnel/actions/runs/39495650155).
  Neqo lifecycle повторён пять раз с cgocheck2/race; NSS close/отмена — восемь раз.
- [NSS](https://github.com/SawaMEN/FoxTunnel/actions/runs/39495650236),
  [Go](https://github.com/SawaMEN/FoxTunnel/actions/runs/39495650303),
  [SDK на трёх ОС](https://github.com/SawaMEN/FoxTunnel/actions/runs/39495650187).
- [24 исходных resource samples и медианы](measurements/2026-10-21/native-backend-metrics.json),
  [происхождение и SHA-256](measurements/2026-10-21/native-backend-provenance.json).

Замер выполнен на synthetic PR merge `6a81cec9`, родители `db426f26` и `b6d33368`;
это не выпуск. Измерения сохранены отдельным коммитом с документацией.
Локально прошли 146 Python-тестов (2 skipped), go vet и пробный Go benchmark runner.

[Pins, FFI, результаты и методика измерений](NATIVE-BACKENDS.md).
Пункты 4–5 подтверждены [CI 39500678054](https://github.com/SawaMEN/FoxTunnel/actions/runs/39500678054):
[шесть свежих наблюдений и версии](measurements/2026-10-21/wire/manifest.json),
[SHA-256 и проверенное происхождение](measurements/2026-10-21/wire/provenance.json),
[сравнение с различиями TLS/H2/H3](measurements/2026-10-21/wire/comparison.json).
Это ограниченное сравнение startup metadata: полная эквивалентность сценариев
не подтверждена; effective QUIC values включают defaults/sentinel декодера.
Локально прошли 149 Python-тестов (2 skipped), проверка ссылок и целостности реестра.
Независимый аудит этапа 5 по-прежнему не предоставлен.
Зелёные interop-тесты не доказывают совпадение fingerprint или превосходство по скорости.

## Этап 7 из 10 — SDK

**Выполнено 6 из 6 задач.** [PR #43](https://github.com/SawaMEN/FoxTunnel/pull/43), поверх PR #42; изменения включены в main через PR #43.

- [x] Версионировать контракт Go SDK и процесса, явно сообщать фактически собранные backends.
- [x] Закрепить отмену setup, SOCKS service и всего Client с изоляцией независимых потоков.
- [x] Предоставить ограниченные по памяти события состояния без блокирования трафика и передачи секретов.
- [x] Добавить машинные ready/stopped события процесса и переносимую EOF-остановку.
- [x] Предоставить внешний process host и подтвердить настоящий H2/H3 payload и освобождение ресурсов.
- [x] Подтвердить 22 обязательных внешних SDK/process сценария на Linux/macOS/Windows и сохранить результаты CI.

Первый путь встраивания — отдельный процесс; библиотека `processhost` использует
только стандартную библиотеку и константы контракта, не загружает NSS/Neqo в host.
Swift/JNI ABI для конкретного приложения не выбран: platform bridges и
VpnService/NetworkExtension относятся к host-интеграции этапа 8; Android-клиент
на этом этапе не изменяется. Встраиваемый Go SDK также сохраняется.
[Контракт SDK и управления процессом](SDK.md).
Подтверждение runtime `034b4fc0`: [CI матрица](https://github.com/SawaMEN/FoxTunnel/actions/runs/39540666188),
22/22 случая на каждой из трёх native ОС (66 выполнений),
[исходные отчёты и проверенные hashes/provenance](measurements/2026-10-21/sdk/provenance.json).
Synthetic checkout `ce1d3d08` и оба родителя проверены; original JSON сохранены
без изменения байтов. Локально прошли полный Go race suite, внешний SDK с реальным
CLI, go vet, govulncheck, core boundaries, ссылки и 149 Python-тестов (2 skipped).

## Этап 8 из 10 — интеграции отложены

По указанию пользователя Hiddify и 3x-ui пока не интегрируются. Android-клиент,
Swift/JNI bridges и приложения-хосты в текущую работу не входят.

## Этап 9 из 10 — релизы

**Выполнено 6 из 6 задач.** [PR #44](https://github.com/SawaMEN/FoxTunnel/pull/44),
изменения включены в main merge-коммитом `bd5fddb3`. Публичный release не создан.

- [x] Закрепить состав двух минимальных Linux NSS архивов и SDK/process/wire metadata.
- [x] Проверить совпадение байтов двух независимых сборок на каждом native runner.
- [x] Проверить install/update/rollback полных NSS архивов с реальным H2/H3 payload и сохранением private config.
- [x] Проверить совместимость с hash-pinned опубликованными alpha.1 архивами в обе стороны и строгие отказы.
- [x] Подготовить проверяемые SHA-256 и provenance без изменения двухархивной схемы поставки.
- [x] Подтвердить native amd64/arm64 матрицу и сохранить отчёты/инструкции релизного кандидата.

Сборки и установка выполняются в изолированных временных каталогах CI.
Повторяемость относится к одному зафиксированному source/toolchain/runner;
совпадение между разными дистрибутивами или компиляторами не заявляется.
Архивы прежнего выпуска используются только для loopback interoperability.
Публичный выпуск не запускается изменением этого плана или обычным merge:
для него остаётся явный version request/tag и проверка подписанного provenance.
[Контракт релизного кандидата и методика](RELEASES.md).
Подтверждение runtime `f48da3bf`: [native release CI](https://github.com/SawaMEN/FoxTunnel/actions/runs/39543757118),
[оригинальные отчёты и проверенное происхождение](measurements/2026-10-21/releases/provenance.json).
Оба native runner подтвердили точное совпадение повторных архивов, 6/6 payload
проверок после install/update/rollback и 2/2 legacy test groups.
Все 8 PR workflows прошли; publish job штатно skipped. Валидация скачанных ZIP,
inner archive SHA-256, состава и metadata выполнена повторно локально.
Кандидаты — `v0.0.0-ci` из synthetic checkout `8f471a6c`, не подписанный публичный
выпуск и не байты будущей версии. Независимый security review остаётся открытым.

## Этап 10 из 10 — оптимизация

**Подтверждено 5 из 6 задач.** Изменения [PR #45](https://github.com/SawaMEN/FoxTunnel/pull/45)
включены в main merge-коммитом `43cd0e7f`; этап 8 отложен.

- [x] Воспроизводимые парные benchmarks с исходными выборками, версиями и hashes.
- [x] Пороги CPU/allocations и отказ при неполных или нестабильных измерениях.
- [x] Оптимизация по профилю с сохранением семантики выбора маршрутов.
- [x] Повторная multi-node/bonding/UDP матрица с race detector.
- [x] Длительные H2/H3 соединения, отмена и восстановление после перезапуска.
- [ ] Ресурсные бюджеты и сохранённые результаты native CI.

[Локальный парный отчёт](measurements/2026-10-21/optimization/local-paired.json)
для runtime `2e0c3184`: 9/9 случаев, по 7 повторов каждой версии.
Все пороги выполнены. Полный Go race suite, пять routing race suites,
три повторных Bond/UDP tunnel suites и 157 Python-тестов (2 skipped) прошли.
Десятиминутные H2/H3 same-destination streams прошли в
[CI 39546631821](https://github.com/SawaMEN/FoxTunnel/actions/runs/39546631821).
Его отдельный десятиминутный resource/restart gate пока выполняется;
последний пункт остаётся открытым до проверки и сохранения отчёта.

Windows launcher теперь ожидает завершения дочернего процесса и передаёт
его exit status. [Native operations CI](https://github.com/SawaMEN/FoxTunnel/actions/runs/39547762455)
прошёл на Linux, macOS и Windows. После исправления прошли 159 Python-тестов,
2 skipped. Единичный сбой Bond с accepted=2/coordinator_dials=1 не повторился
в 100 локальных запусках и полном
[security rerun](https://github.com/SawaMEN/FoxTunnel/actions/runs/39547762431).
Его причина пока не установлена; исправленным он не объявляется.

[Методика и пороги этапа](OPTIMIZATION.md).

Loopback и scheduler microbenchmarks не доказывают ускорение WAN или
сетевую неразличимость. Старые PASS не засчитываются как новые измерения.

Следующие рубежи: alpha с актуальным ядром и контрактом; beta с wire/TCP/UDP
совместимостью; RC с security review и интеграционными E2E; v1 со стабильными
API и документированными гарантиями. NSS/Neqo и другие исследования могут
выполняться отдельно от стабилизации базового Go/H2.
