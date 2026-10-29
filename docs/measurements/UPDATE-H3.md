# Neqo/H3: результат этапа 5

Устранены частые Go-аллокации scalar out-параметров cgo. В двух измеренных
loopback-сценариях число Go allocations/exchange снизилось на 40–44%.
Ускорение обмена и снижение CPU/RSS не подтверждены.

## Ревизии и воспроизводимость

- База: `191871b51a00627ce79b28d6c103168da77ab84f`.
- Проверенный код: `0a692304cbc79b9d5286ae9b667085bf5573a6c8`.
- [CI с измерением](https://github.com/SawaMEN/VetroffProxy/actions/runs/39728855358),
  artifact `update-h3-profile` (ID `12404606126`).
- Go 1.26.10, Neqo 0.33.0, NSS 3.130; lock — `scripts/neqo.lock.json`.
- Native архив общий для двух бинарников; версии и hashes записаны в JSON.
- CPU: AMD EPYC 7763 64-Core Processor. Linux amd64, два Go P на процесс.

Workflow `.github/workflows/neqo-experiment.yml` собирает оба test binary
из указанных immutable ревизий, используя один native runtime. Компиляция
вне измеряемых процессов. После прогрева идут семь повторов с чередованием
порядка base/head и Go-H3/Neqo-H3. Каждый small-процесс выполняет 250 обменов
64B, bulk — 16 обменов 1MiB. В одном процессе работают клиент, proxy и echo;
setup исключён из Go ns/op, но входит в process CPU/RSS.

Сохранённые данные:

- [Исходный baseline и профили](update-h3-baseline.json).
- [Профили проверенного кандидата](update-h3-candidate.json).
- [Парное сравнение, все повторы, min/max/MAD, hashes и toolchains](update-h3-comparison.json).

## Парное сравнение Neqo

Медианы семи повторов; время — один echo-обмен, не чистая transport latency.

| Сценарий | Go allocs/op, до → после | Go B/op, до → после | Время ns/op, до → после |
|---|---:|---:|---:|
| 64B | 42 → 25 (−40.5%) | 1423 → 1254 (−11.9%) | 297834 → 299213 |
| 1MiB | 11787 → 6637 (−43.7%) | 1539004 → 1493868 (−2.9%) | 29665625 → 29490468 |

| Сценарий / ревизия | Время min–max, ns | Относительный MAD времени | Process user/system CPU, s | Peak RSS, KiB |
|---|---:|---:|---:|---:|
| 64B / base | 295501–304711 | 0.78% | 0.062427 / 0.072296 | 27352 |
| 64B / head | 295018–307988 | 0.48% | 0.062698 / 0.070688 | 27272 |
| 1MiB / base | 26764443–30818055 | 3.67% | 0.500694 / 0.509872 | 34468 |
| 1MiB / head | 27757045–31386484 | 4.69% | 0.510540 / 0.495193 | 34792 |

Отношение медиан времени head/base: 1.0046 для 64B и 0.9941 для 1MiB.
Медиана отношений внутри пар: 0.9984 и 1.0200 соответственно. Эти небольшие
различия не дают основания заявлять ускорение. Контрольный Go-H3, код которого
не менялся, показал изменение медианы времени −4.1%/+4.6%; его allocs/op —
30→30 и 9053→9130. CPU/RSS Neqo также меняются в обе стороны.

## Почему изменён этот участок

В исходном alloc_objects профиле `engine.event` занимал около 19%/29%
объектов для small/bulk, `engine.output` — около 12%/7%. Временные scalar
переменные уходили в Go heap при передаче их адресов в cgo. Теперь out-поля
принадлежат engine и используются его единственным actor на закреплённом
OS thread. Они обнуляются перед каждым вызовом, включая пустой event, где
ABI пишет только kind. В объекте нет указателей на другие Go-объекты;
C/Rust не сохраняет адреса out-полей. Размер дополнительного состояния
фиксирован, wire и ABI не менялись.

Новый `TestUpdateEmptyEventHasNoGoAllocation` проверяет нулевые Go-аллокации
при пустом event и отсутствие устаревших stream/arg. В новых top-таблицах
аллокаций `engine.event/output/read` больше не входят в первые 20 строк.
Главный источник bulk allocated bytes — копирование входящих датаграмм —
сохранён: его устранение требует отдельного бюджета памяти receive-очереди.

## Проверки и ограничения

[Go CI](https://github.com/SawaMEN/VetroffProxy/actions/runs/39728855302),
[NSS CI](https://github.com/SawaMEN/VetroffProxy/actions/runs/39728855269),
[build audit](https://github.com/SawaMEN/VetroffProxy/actions/runs/39728855284) и
[Neqo CI](https://github.com/SawaMEN/VetroffProxy/actions/runs/39728855358) прошли.
Neqo CI включает vet, полные root/external race-тесты с `nss,neqo`,
interop/trust/UDP/cancellation/duplex/reset/backpressure и повторные lifecycle
тесты. `GOEXPERIMENT=cgocheck2` вместе с race detector повторяет
`TestStage6|TestUpdate` пять раз. Первая версия кандидата `55d3dcc` не прошла
native-компиляцию из-за позиционного литерала расширенной структуры;
проверенная ревизия исправляет инициализацию по имени поля.

Начальный baseline запускал child непосредственно из Python; все RSS там
получились 43308 KiB. Его RSS не используется для сравнения памяти из-за
возможного унаследованного пика до exec. В парном сравнении применяется
`scripts/native_resource_runner.c`: маленький launcher после собственного
exec запускает benchmark и снимает его wait4 rusage. Локальная проверка с
64 MiB в Python-родителе подтвердила отсутствие этого нижнего порога.
Legacy-вызов `native_backend_metrics.py` без resource runner сохраняет старый
способ измерения; для выводов этапа используется только парный JSON выше.

Go allocation profiles не измеряют Rust/C allocations. Go CPU profiles видят
native время как cgo и не раскрывают внутренние Rust stacks. Raw profiles
не публикуются; сохранены только таблицы функций. Результаты не являются
WAN-тестом, измерением Firefox или доказательством fingerprint-эквивалентности.
