# Этап 4/8 — Firefox TLS, H2, QUIC/H3: проверяемые отличия

Ветка: `up`. Статус: старт этапа 4, **1 из 5 задач** после
подтверждения в CI. Этап 3 остаётся 4/5, WAN на независимых VDS ещё
не выполнен.

## Реальные захваты и ограничения

Эталон: сохранённый захват настоящего Firefox 158 Linux из
`docs/measurements/2026-10-18/firefox-158-linux.json`.
Промежуточный FoxTunnel NSS из
`docs/measurements/2026-10-19/nss-firefox158-page.json`.

**Они не идентичны по TLS ClientHello.** Среди зарегистрированных
различий — cipher suites, расширения и их порядок, TLS supported
versions, ALPN, часть signature algorithms, JA3. Причина отчасти
намеренная: FoxTunnel использует TLS 1.3-only и H2-only ALPN там,
где Firefox предлагает также более старый TLS и HTTP/1.1.
Слепая подмена ClientHello без сохранения реального поведения TLS —
неприемлемый путь к имитации отпечатка.

Для H2 сохранённый захват FoxTunnel исторически отличался порядком
SETTINGS и рекламируемым MAX_HEADER_LIST_SIZE. В текущем NSS
`internal/h2profile/settings_conn.go` уже есть ограниченный переписыватель
начальных SETTINGS; существующие wire-тесты
`internal/tunnel/h2_profile_nss_test.go` проверяют порядок, размеры окон,
реальное продление flow control и TLS-verification. Это **не** означает
полного соответствия Necko: HPACK, заголовки, cookies, приоритеты,
распределение DATA по кадрам и тайминги не сопоставлены.

H3/QUIC parity пока неизвестна: без настоящего endpoint-декодированного
захвата Firefox и текущей Neqo отсутствующие транспортные параметры
считаются **not_measured**, а не совпадениями.

## Первый подэтап — доказуемая целостность измерений

Новый CI `Stage 4 Firefox Fingerprint Evidence` работает на ветке
`up`, отдельно от устаревшего workflow на `update`. Он:

- Проверяет соответствие JA3 и JA3 MD5 исходным TLS полям; отбрасывает
  несовместимые или повреждённые захваты.
- Проверяет диапазоны H2 SETTINGS и отсутствие повторяющихся QUIC/H3
  идентификаторов; не выдаёт синтетические строки за наблюдение.
- Ожидает реальные исторические отличия Firefox и NSS, а не ложный
  флаг `metadata_equal=true`.
- Повторяет H2 wire/flow-control тесты для Go TLS и NSS с сохранением
  ALPN и ошибок отмены.

Бенчмарки Stage 3 и эти фикстуры не являются независимыми
браузерными захватами за текущий день.

### Как повторить аудит локально

~~~sh
python3 -m unittest discover -s scripts -p test_fingerprint_audit.py -v
python3 scripts/fingerprint_audit.py \
  --firefox docs/measurements/2026-10-18/firefox-158-linux.json \
  --foxtunnel docs/measurements/2026-10-19/nss-firefox158-page.json \
  --out /tmp/fox-stage4-historical.json
go test ./internal/tunnel -run '^TestHTTP2ReceiveProfile' -count=1
# Linux с CGO, libnss3-dev/libnspr4-dev:
go test -tags nss ./internal/tunnel -run '^TestNSSHTTP2ReceiveProfile' -count=1
~~~

Используйте приватный каталог для новых захватов и не загружайте
ключи, сертификаты приватных серверов, домены и содержимое HTTP в Git.

## Этап 4 — 5 задач

- [x] Установить измеряемый исторический baseline Firefox/NSS, целостность
  JA3 и QUIC/H3, запустить H2 регрессии в CI ветки up.
- [ ] Получить свежие сравнимые захваты TLS/ALPN и HTTP/2 первого
  кадра для Firefox и текущего NSS на одинаковом GET/CONNECT.
- [ ] Сравнить HTTP/2 запросы целиком: заголовки, HPACK, приоритеты,
  WINDOW_UPDATE, порядок DATA и размеры TLS records.
- [ ] Получить endpoint-декодированные QUIC transport parameters и H3
  SETTINGS для настоящего Firefox и актуального Neqo под одинаковой
  нагрузкой; устранить доказанные несовпадения без подделки пакетов.
- [ ] Подтвердить функциональность, отсутствие утечек и сравнимость
  вариантов на внешних сетях и независимой инфраструктуре.

Полное совпадение всех перечисленных метаданных **само по себе**
не доказывает неотличимость от Firefox, устойчивость к DPI или
работоспособность при мобильных «белых списках».
