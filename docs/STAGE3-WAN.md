# Этап 3/8 — сравнение baseline FoxTunnel, candidate FoxTunnel и VLESS

**Статус:** скрипты готовы к внешнему WAN-эксперименту. **Реальные WAN-замеры не выполнялись.**

## Методика

Запустите одновременно три отдельные SOCKS5 клиента:

1. baseline FoxTunnel до этапа 3, commit 23d3ba78dcf77fb810a26ef27b1a30133490ce86
2. candidate FoxTunnel из ветки up (запишите **полный** SHA)
3. Xray/VLESS с явно зафиксированной версией и режимом.

У baseline и candidate обязаны совпадать: TLS backend, H2/H3,
fingerprint, padding, конфигурация сервера и ограничения ресурсов.
Отдельные порты SOCKS (например 1080/1081/1082), одинаковые классы
VDS, регион, маршрут, MTU и firewall. Один контролируемый внешний TCP
echo-сервер должен быть доступен всем exit. Три клиента на одной VM
**не доказывают WAN**. Тип VDS, независимость, режим Xray и бинарные
SHA оператор обязан проверить вручную.

Скрипт чередует порядок трёх SOCKS-клиентов и проверяет echo целиком.
Сырая запись временная и приватная; итоговые отчёты без адресов,
секретов, hostname и PID. Операторская отметка WAN НЕ является
независимым подтверждением — в JSON поле wan_verified_by_tool=false.

Версия отчёта **schema=2** теперь включает `started_at_utc`,
`finished_at_utc` и `warmup_failures` для каждого клиента.
Gate требует, чтобы измерение полностью укладывалось в один календарный
UTC-день, имело корректную длительность и **не имело ошибок прогрева**.
Это исключает неверное зачисление многочасового измерения на следующий день
и пропуск нестабильного SOCKS при первых запросах. Старые schema=1 отчёты
несовместимы с обновлённым gate и должны быть получены заново.

## Пример на Linux, день 1

~~~sh
mkdir -m 700 -p "$HOME/ft-stage3-private"
python3 scripts/stage3_wan.py \
  --baseline-socks 127.0.0.1:1080 \
  --candidate-socks 127.0.0.1:1081 \
  --vless-socks 127.0.0.1:1082 \
  --baseline-sha 23d3ba78dcf77fb810a26ef27b1a30133490ce86 \
  --candidate-sha "$CANDIDATE_FULL_COMMIT_SHA" \
  --fox-transport h2-connect --vless-transport reality-vision \
  --target echo.private.example:9000 \
  --scenario small --rounds 30 --parallel 2 --warmup 2 \
  --environment wan --confirm-independent-vds \
  --baseline-pid 1111 --candidate-pid 2222 --vless-pid 3333 \
  --out "$HOME/ft-stage3-private/day1-small.json"
~~~

Замените фиктивные PID, SHA и echo target настоящими.
На другом VDS откройте доступ к TCP echo **только с IP разрешённых
exit через firewall**. Не выставляйте неавторизованный echo всему интернету.
Для локальной лаборатории используйте --environment lab без
--confirm-independent-vds; лабораторный отчёт не может пройти WAN gate.

Повторите команду для --scenario bulk (по умолчанию 32 МиБ; small=1 КиБ)
в отдельный day1-bulk.json. Сделайте по одному отчёту small и bulk на
**трёх разных UTC-днях**, не меняя SHA, параметры, порты и расположение
оборудования. CPU/RSS через Linux /proc/PID измеряются у всех трёх
клиентских процессов. Для WAN bulk все три PID обязательны. CPU/RSS
удалённых серверов здесь не измеряются.

## Трёхдневный gate

~~~sh
python3 scripts/stage3_wan_gate.py \
  --report "$HOME/ft-stage3-private/day1-small.json" \
  --report "$HOME/ft-stage3-private/day1-bulk.json" \
  --report "$HOME/ft-stage3-private/day2-small.json" \
  --report "$HOME/ft-stage3-private/day2-bulk.json" \
  --report "$HOME/ft-stage3-private/day3-small.json" \
  --report "$HOME/ft-stage3-private/day3-bulk.json" \
  --out "$HOME/ft-stage3-private/verdict.json"
~~~

Схема отчёта **version=2**. Gate пересчитывает измерения из всех samples,
не доверяет summary, отвергает дубликаты дней, смешение конфигураций,
неполные раунды, ошибки прогрева, неполные/пересекающие полночь UTC
интервалы и фальшивую отметку WAN-верификации.

Условия каждого дня: не менее 30 echo на прокси, успешность >=99%
для всех, отсутствие повреждения; small p95 полного CONNECT+echo
candidate <=110% baseline и VLESS; bulk медиана Mbps candidate
>=90% baseline и VLESS, p95 CONNECT <=110% каждого. Для bulk CPU
и RSS candidate <=120% baseline и VLESS.

**Условный PASS означает только отсутствие существенной регрессии
при операторской аттестации WAN.** Он НЕ доказывает ускорение относительно
baseline, превосходство VLESS, подлинность VDS, Firefox fingerprint или
обход DPI. Для такого вывода требуются многократные сессии на равном
оборудовании, проверка маршрутов, нативный учёт CPU NSS и анализ
разброса результатов.

## Офлайн тестирование

~~~sh
python3 -m py_compile scripts/stage3_wan.py scripts/stage3_wan_gate.py
python3 -m unittest discover -s scripts -p test_stage3_wan.py -v
~~~

Этот инструмент делает шаг 5 **готовым к испытанию**, но статус
этапа остаётся **4 из 5 (80%)** до реальных WAN/VDS отчётов. CI тестирует
исключительно подставные локальные SOCKS-серверы, не арендованные VDS.
