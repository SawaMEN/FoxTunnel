# Этап 3/8 — TCP Fast Path: буферы и проверяемые оптимизации

**Ветка:** up. **Статус:** первая реализация (буферы копирования); остальные
изменения Fast Path требуют профилирования и проверки результата.

## Что изменено

1. `internal/tunnel/fastcopy.go`: общая повторно используемая scratch-память
   32 KiB для обходного пути стандартного `io.Copy`. Избегаем получения
   буфера из `sync.Pool`, если доступны `io.WriterTo` или `io.ReaderFrom`.
   В конце операции buffer очищается, чтобы текст пользователей не оставался
   в общем пуле.
2. Заменены `io.Copy` в обеих горутинах клиентского `streamConn` и в двух
   направлениях server CONNECT. Ошибки, graceful EOF, CloseWrite и политика
   отмены остаются на прежнем уровне.
3. Две отдельные `net.Pipe` в `streamConn` пока сохраняются намеренно:
   объединение в одну двунаправленную pipe ломает независимый half-close.
   Более агрессивный zero-copy требует новой реализации deadlines и тестов.
4. Юнит-, fuzz-, race-тесты и микробенчмарки сравнивают **одинаковый поток**
   через stdlib `io.Copy` и `fastCopy`; отдельный CI не блокирует сборку
   на основании шумных величин производительности GitHub runner.

## Команды

~~~sh
go test -race ./internal/tunnel -run '^(TestFastCopy|TestStreamOutlivesSetupTimeoutAndHalfClose|TestParallelStreams)' -count=1
go test ./internal/tunnel -run '^$' -fuzz '^FuzzFastCopy$' -fuzztime=2000x
go test ./internal/tunnel -run '^$' -bench '^BenchmarkFastCopyBaselineVsPool$' -benchmem -benchtime=200ms -count=5
~~~

Сравнивайте ns/op, B/op, allocs/op и B/s **только при одинаковом железе,
Go toolchain, типе transport и параметрах**. Подтверждённое повышение скорости
и снижение CPU на реальной сети отсутствует. Перед следующими оптимизациями
нужно снять профили heap/CPU и block на TCP bulk/small с теми же параметрами,
что используются в `docs/STAGE1-VLESS.md`.

## Воспроизводимые профили H2/H3 и NSS (шаг 2)

Теперь есть отдельный офлайн-профилировщик \`scripts/stage3_profile.py\`.
Он запускает реальные loopback SOCKS → FoxTunnel → локальный TCP echo
бенчмарки для **одного транспорта и одного размера** за запуск:

| Вариант CLI | Реальная трасса на loopback | Теги Go |
|---|---|---|
| \`go-h2\` | H2 CONNECT + Go TLS 1.3 | Без тегов |
| \`go-h3\` | H3 POST + quic-go | Без тегов |
| \`nss-h2\` | H2 CONNECT + Mozilla NSS TLS | \`-tags nss\`, Linux + CGO |

Сценарии \`small\` = 64 байта и \`bulk\` = 1 МиБ, повторяемые обмены
внутри уже открытого соединения. Это ближе к изолированному профилированию
быстрого пути, **не** полный CONNECT RTT. Для сценариев 1 КиБ/32 МиБ на
независимых VDS остаётся \`docs/STAGE1-VLESS.md\`.

Пример на Linux (внешняя приватная папка, не внутри Git):
~~~sh
python3 scripts/stage3_profile.py --variant go-h2 --scenario small \
  --benchtime 3s --out /tmp/ft-profiles/go-h2-small
python3 scripts/stage3_profile.py --variant go-h3 --scenario bulk \
  --benchtime 3s --out /tmp/ft-profiles/go-h3-bulk
python3 scripts/stage3_profile.py --variant nss-h2 --scenario bulk \
  --benchtime 3s --out /tmp/ft-profiles/nss-h2-bulk
~~~
Каталог \`/tmp/ft-profiles\` следует создать заранее с правами \`0700\`.
Каждый выходной каталог создаётся однократно, \`0700\`, без перезаписи.
Внутри: \`cpu.pprof\`, \`mem.pprof\`, \`block.pprof\`, \`mutex.pprof\`,
\`go-test.log\`, \`summary.json\`. Файлы с правами \`0600\` на Linux.

Анализ в локальной среде (не размещать сырые профили в сети):
~~~sh
go tool pprof -top /tmp/ft-profiles/go-h2-small/cpu.pprof
go tool pprof -top -alloc_space /tmp/ft-profiles/go-h3-bulk/mem.pprof
go tool pprof -top /tmp/ft-profiles/nss-h2-bulk/block.pprof
~~~

Для \`nss-h2\` нужен работающий CGO и dev-пакеты NSS/NSPR. Go CPU pprof
не учитывает потребление CPU **внутри нативного C NSS**, поэтому для
достоверной оценки NSS↔Go FFI необходим дополнительный нативный профайлер
и измерение полного процесса. CPU/heap/block/mutex Go-профили нельзя
интерпретировать как абсолютную стоимость C-библиотеки.

CI выполняет шесть парных профилей (3 варианта × 2 размера), но не загружает
сырые \`.pprof\` в артефакты. Метрики CI не являются повторяемым WAN
бенчмарком, а \`pprof\` могут содержать пути к файлам и другую служебную
информацию. Для анализа реальных регрессий сохраняйте приватные профили
и повторяйте по несколько запусков на одинаковом железе и коммите.

## Этап 3: задачи (план 5 подзадач)

- [x] Ограничение heap-аллокаций scratch buffers и защита Fast Path тестами.
- [x] Воспроизводимый захват CPU/heap/block/mutex под H2, H3 и NSS для small/bulk (loopback; CI); фактический анализ профилей и WAN-прогоны ещё впереди.
- [ ] Испытать уменьшение лишних копий/потоков без потери half-close.
- [ ] Отдельно измерить NSS↔Go FFI, исключить лишние передачи/преобразования.
- [ ] Подтвердить улучшение на независимых VDS против исходной версии и VLESS.

**Примечание:** Fast Path не реализует новую обфускацию и не проверяет обход DPI.
