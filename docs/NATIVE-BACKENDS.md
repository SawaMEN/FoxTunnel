# NSS и Neqo: этап 6 из 10

Этап состоит из пяти задач: целостность pins; FFI lifecycle; CPU/RSS/скорость;
сопоставимые TLS/H2 captures Firefox/NaiveProxy/FoxTunnel; endpoint-decoded H3
captures тех же трёх реализаций. Все пять пунктов реализованы в PR #41/#42.
Новые captures охватывают начало соединения в контролируемом стенде;
полная эквивалентность приложений и независимый аудит этим не подтверждаются.

## Закреплённые входы

| Вход | Источник истины | Дополнительная сверка |
|---|---|---|
| Neqo 0.33.0, commit `1ec4c2a3ccd7ada264112d1b70b070381557d844` | scripts/neqo.lock.json | Cargo.lock всех neqo-* и исходников из Mozilla Neqo, Cargo.toml, Go API Version/Revision |
| nss-rs 0.16.1, commit `ba8a3f6acffc7e25749054969ccbbb3ca615df7f` | scripts/neqo.lock.json | Cargo.lock version/source |
| Rust 1.99.1 | scripts/neqo.lock.json | rust-toolchain.toml и фактический rustc перед сборкой |
| NSS 3.130 из Firefox 158.0 | scripts/mozilla-runtime.lock.json | Neqo pin, SHA-256 архива, библиотеки, NSS_GetVersion перед приёмом backend |
| NSS/NSPR headers | scripts/neqo.lock.json | чистый Git checkout commit и SHA-256 NSPR архива |

Это фиксация выбранной сборки, а не утверждение, что версии самые новые.
Релизные обычные NSS-сборки и экспериментальная pinned Mozilla сборка — разные
варианты: системный NSS из отдельного CI нельзя выдавать за pinned runtime.
Новые тесты намеренно меняют transport/qpack/common source, compiler и Go API
revision и требуют отказа до native build.

## FFI ownership

Neqo engine принадлежит одному Go actor, закреплённому за OS thread. Rust не
сохраняет Go pointers. Буферы заимствуются синхронно на отдельный вызов ABI;
после принятия команды actor обязан вернуть ответ либо полностью завершиться
до возврата caller. Отмена запроса закрывает поток и разблокирует upload/read.

Новые тесты создают шесть поколений настоящего QUIC engine с четырьмя активными
потоками в каждом; закрывают один поток конкурентно с чтением, затем отменяют
остальные и требуют пустых live/origin pools. Отдельный управляемый тест
удерживает принятую команду после отмены, подтверждая возврат ownership только
после actor reply. Rust проверяет null/oversized input, panic containment и
границы metadata. NSS проверяет конкурентное закрытие и отмену handshake.

CI повторяет lifecycle с `GOEXPERIMENT=cgocheck2` и `-race`. Это проверки Go/cgo
контракта, а не полная верификация Rust/C памяти или замена ASan/аудита.

## Сопоставимый loopback-стенд

Все четыре варианта выполняются одним test binary, на одном Linux amd64 runner,
последовательно. В обычном benchmark-цикле Go-H2 и NSS-H2 отличаются TCP TLS;
Go-H3 и Neqo-H3 — клиентским HTTP/3 engine. Сервер и destination echo используют
один и тот же Go-код. Измеряется полный SOCKS → proxy → echo путь, padding выключен.

- Small: 64 байта, 250 обменов в измеряемом цикле.
- Bulk: 1 MiB, 16 обменов в измеряемом цикле.
- Три повтора; порядок вариантов меняется; `-test.cpu=2`; без race instrumentation.
- Payload проверяется; отсутствие строки benchmark/PASS, ошибка или другое
  число итераций не засчитывается.
- Компиляция выполняется до измерений. Каждый sample — новый дочерний процесс.

`native_backend_metrics.py` получает CPU user/system и peak RSS через Linux
`wait4` для конкретного child. CPU/RSS включают client, server, echo, калибровку,
setup и cleanup. `ns/op` и MB/s относятся к измеряемому циклу Go benchmark.
MB/s считает payload одного направления, хотя обмен включает upload и echo.
Go B/op и allocs/op не учитывают native allocations; RSS учитывает память всего
процесса, включая NSS/Rust, но не выделяет её по engine.

Отчёт содержит 24 samples, медианы, source commit/dirty flag, hash test binary,
lockfile, версии, CPU model/kernel и hash каждого stdout. В артефакт CI попадает
только JSON-агрегат, без raw pprof/pcap. Числа подтверждают конкретный loopback run,
не превосходство над Firefox/NaiveProxy или показатели реальных VDS/операторов.

Запуск после `python3 scripts/build_neqo.py` и подключения созданного env.sh:

~~~sh
go build -tags nss,neqo -o /tmp/foxtunnel-native ./cmd/foxtunnel
/tmp/foxtunnel-native version --json > /tmp/native-versions.json
go test -c -tags nss,neqo -o /tmp/native-backend.test ./internal/tunnel
python3 scripts/native_backend_metrics.py --binary /tmp/native-backend.test \
  --versions /tmp/native-versions.json --out /tmp/new-native-metrics.json
~~~

## Полученные результаты

[CI run](https://github.com/SawaMEN/FoxTunnel/actions/runs/39495650155),
PR runtime `b6d33368`, synthetic checkout `6a81cec9` (оба родителя проверены).
AMD EPYC 7763, Linux amd64, Go 1.26.9, pinned NSS 3.130/Neqo 0.33.0.
[Полные 24 samples](measurements/2026-10-21/native-backend-metrics.json) и
[происхождение](measurements/2026-10-21/native-backend-provenance.json) сохранены
из CI artifact; SHA-256 ZIP совпал с digest GitHub.
CLI собран как dev: его `commit: unknown` и `dirty: true` — build defaults;
отдельно измеренный `checkout_commit` известен, `worktree_dirty: false`.

Медианы трёх повторов. CPU — user+system конкретного child целиком, в миллисекундах;
peak RSS — MiB. Колонки ns/op/MB/s и process CPU/RSS имеют разные границы времени,
описанные выше; CPU не является стоимостью одного exchange.

| Backend | Сценарий | µs/exchange | MB/s | CPU процесса, ms | Peak RSS, MiB |
|---|---|---:|---:|---:|---:|
| go-h2 | small | 198.2 | 0.32 | 95.3 | 26.0 |
| go-h2 | bulk | 3874.3 | 270.65 | 158.3 | 27.0 |
| nss-h2 | small | 251.0 | 0.25 | 119.4 | 24.2 |
| nss-h2 | bulk | 4889.1 | 214.47 | 193.1 | 28.3 |
| go-h3 | small | 200.1 | 0.32 | 95.4 | 24.6 |
| go-h3 | bulk | 9924.3 | 105.66 | 366.0 | 31.0 |
| neqo-h3 | small | 332.7 | 0.19 | 151.3 | 27.8 |
| neqo-h3 | bulk | 29624.7 | 35.40 | 1015.1 | 34.9 |

В этом конкретном прогоне Neqo-H3 уступает Go-H3 по bulk throughput и использует
больше CPU/RSS. Это исходная точка для оптимизации, не вывод о любых сетях или
преимущество NSS/Neqo над другими реализациями. Между тремя короткими повторами
не измерен полноценный доверительный интервал, а общие runner могут испытывать шум.

## Свежие TLS/H2 и endpoint-decoded QUIC/H3

[CI run 39500678054](https://github.com/SawaMEN/FoxTunnel/actions/runs/39500678054)
получил все шесть наблюдений на одном Linux amd64 runner. Runtime head
`03e9c9eab0e84d66def2e38ff1df751bcb5a70fa`; synthetic checkout
`bb8914a42c3e29d36fc16916ed05e42fe01d283b`, родители проверены.
[Исходный manifest](measurements/2026-10-21/wire/manifest.json),
[происхождение и хеши](measurements/2026-10-21/wire/provenance.json) и
[полное сравнение](measurements/2026-10-21/wire/comparison.json) сохранены
без изменения байтов из CI artifact. SHA-256 ZIP сверён с digest GitHub.
Firefox 158.0 и NaiveProxy 154.0.8037.49 взяты из закреплённых архивов;
проверены версии исполняемых файлов и их хеши. Firefox source commit неизвестен
и не выводится из номера версии; archive/executable identity дана в manifest.

| Субъект | TLS/H2 | QUIC/H3 |
|---|---|---|
| Firefox 158.0 | [JSON](measurements/2026-10-21/wire/firefox-h2.json) | [JSON](measurements/2026-10-21/wire/firefox-h3.json) |
| NaiveProxy 154.0.8037.49 | [JSON](measurements/2026-10-21/wire/naive-h2.json) | [JSON](measurements/2026-10-21/wire/naive-h3.json) |
| FoxTunnel NSS / Neqo | [JSON](measurements/2026-10-21/wire/foxtunnel-h2.json) | [JSON](measurements/2026-10-21/wire/foxtunnel-h3.json) |

Одинаковая граница сравнения — холодное соединение с локальным endpoint,
TLS 1.3 либо QUIC v1, IPv4 loopback и проверенный localhost SNI. Endpoint
никогда не перенаправляет запрос к внешнему destination. Firefox делает GET,
Naive — CONNECT, FoxTunnel — CONNECT/POST: `scenario_equivalence_verified: false`.
Это сравнение начальных управляющих метаданных, не всей страницы или туннельной нагрузки.
Firefox использует новый профиль, лабораторный CA, принудительное H3 test mapping,
разрешение H3 с импортированным CA и отключённый content sandbox только в CI.
Это условия стенда, не параметры обычного пользовательского браузера.
Проверки цепочки CA и hostname включены. DNS family/failover не измерены.

H3 декодируется на endpoint через типизированные события quic-go 0.64.0:
выбираются remote transport parameters и первые SETTINGS. Сохраняются только
выбранные эффективные значения, включая defaults декодера. В частности,
`max_udp_payload_size = 4611686018427387903` — внутренний sentinel
`protocol.MaxByteCount` при отсутствии параметра, а не объявленный размер UDP
или RFC default на проводе. Наличие и порядок исходных QUIC параметров, CID,
заголовки запросов, ключи, pcap и raw qlog не сохраняются. Размер первого
QUIC Initial datagram измеряется отдельно на UDP socket.

| Сравнение с Firefox | TLS: different / equal / not observed | H2: different / equal | H3: different / equal |
|---|---:|---:|---:|
| FoxTunnel | 8 / 4 / 1 | 5 / 2 | 2 / 3 |
| NaiveProxy | 7 / 6 / 0 | 5 / 2 | 3 / 2 |

У обеих реализаций `metadata_equal: false`. Даже совпадение выбранных полей
не доказывает неразличимость, поведение в WAN или обход DPI/ТСПУ.
[Реестр доказательств](AUDIT-READINESS.md) содержит все шесть новых captures;
исторические результаты сохраняют прежнюю идентичность. Независимый review
этапа 5 остаётся отдельным открытым пунктом.

## Минимальная версия Go после проверки безопасности

Финальный CI обнаружил GO-2026-6809 в стандартной библиотеке Go 1.26.9
(вызов `crypto/x509.Certificate.Verify` из bootstrap). Go 1.26.10 содержит
исправление crypto/x509: [официальная история выпуска](https://go.dev/doc/devel/release#go1.26.10).
Минимальная версия обоих Go-модулей и все явные CI pins обновлены до 1.26.10;
проверка govulncheck сохранена. Версии и байты уже полученных измерений
на Go 1.26.9 не переписаны: это историческая baseline, не выпуск готового бинарника.
