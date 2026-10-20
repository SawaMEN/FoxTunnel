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

## Этап 3: задачи (план 5 подзадач)

- [x] Ограничение heap-аллокаций scratch buffers и защита Fast Path тестами.
- [ ] Базовые профили CPU/heap/block под H2, H3 и NSS для small/bulk.
- [ ] Испытать уменьшение лишних копий/потоков без потери half-close.
- [ ] Отдельно измерить NSS↔Go FFI, исключить лишние передачи/преобразования.
- [ ] Подтвердить улучшение на независимых VDS против исходной версии и VLESS.

**Примечание:** Fast Path не реализует новую обфускацию и не проверяет обход DPI.
