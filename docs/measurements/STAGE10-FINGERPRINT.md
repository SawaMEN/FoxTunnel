# Этап 10 из 11 — Firefox, FoxTunnel и NaiveProxy

**Ветка:** update. **Метод:** сравнение только реально полученных наблюдений.
Неизмеренное не считается совпадением. Никакой «оценки похожести» или заявления
об обходе ТСПУ из метаданных TLS/HTTP/2/QUIC не следует.

## Исходные измерения

- [Firefox 158.0 Linux, 18 октября](2026-10-18/firefox-158-linux.json):
  контролируемый локальный HTML GET через HTTPS/HTTP2
- [FoxTunnel NSS 3.130, этап 2, 19 октября](2026-10-19/nss-firefox158-page.json):
  аналогичный page GET, но **до этапа 3**, когда был изменён порядок HTTP2 SETTINGS
- [Neqo локальные интероперабельные проверки](2026-10-19/neqo/README.md):
  успешно работающий H3 — не сохранённый QUIC/HTTP3-отпечаток
- Достоверных снимков **NaiveProxy**, **Firefox QUIC/H3** и **Neqo QUIC/H3**
  для тройного сравнения пока нет. Их отсутствие отражается явно

Исторические различия NSS/FoxTunnel и Firefox включают набор TLS cipher suites,
список и порядок расширений, поддержку версий TLS (только 1.3 в FoxTunnel),
алгоритмы подписи, ALPN и набор/порядок HTTP2 SETTINGS. При этом поддерживаемые
группы, key shares и величина начального WINDOW_UPDATE совпадали в сохранённом
снимке. Эти выводы **не относятся автоматически к текущему коду**.

## Отчёт из измерений

~~~sh
python3 scripts/fingerprint_audit.py \
  --firefox docs/measurements/2026-10-18/firefox-158-linux.json \
  --foxtunnel docs/measurements/2026-10-19/nss-firefox158-page.json \
  --out stage10-historical-private.json
~~~

Автоматическая матрица сравнивает исходный порядок TLS/HTTP2 полей и значения
каждого HTTP2 SETTINGS ID; отдельно отмечает QUIC/HTTP3. Статусы:
`equal`, `different`, `not_observed` и `not_measured`.
Для всех исходных файлов сохраняется SHA-256, но не локальный путь к ним.
JSON создаётся один раз с правами 0600, без SNI/IP/паролей/путей.

Дополнительный строгий флаг `--require-complete` завершает команду с ошибкой,
если отсутствует хотя бы один клиентский профиль TLS/H2 или QUIC/H3 у
Firefox, FoxTunnel либо NaiveProxy. Совпадение части полей не скрывает
неполный набор измерений.

## Новое текущее измерение NSS/H2

Специальный [workflow Stage 10](../../.github/workflows/stage10-fingerprint.yml)
на Linux amd64 собирает закреплённый Mozilla NSS 3.130 + Neqo и инструмент
`ft-webprofile` из ветки `update`, создаёт краткоживущий локальный
TLS-сертификат, запускает прямой H2 GET в режиме:
`--sample nss --scenario page --tls-client-profile firefox-158
--h2-receive-profile firefox-158`.
Новый JSON и сравнение с сохранённым Firefox 158 появляются как артефакты
GitHub Actions, помеченные **current NSS vs historical Firefox**.
Workflow **не запускает Firefox**; устаревший эталон используется как
ориентир, а не как синхронный контроль по времени/маршруту.

Сеть H2 SETTINGS зашифрована. Локальный fixture видит их на своём
endpoint после TLS — это не пассивный TCP capture доступный наблюдателю.

## Как получить NaiveProxy для честного сравнения

Разверните независимо настоящий NaiveProxy с его Chromium networking,
настройте исходящее соединение на **тот же контролируемый endpoint**
`ft-webprofile --listen 127.0.0.1:PORT --cert ... --key ... --out naive.json`
без `--sample`. NaiveProxy должен использовать **внешний TLS-туннель**
до сервера, а не локальный TLS браузер→прокси; обеим реализациям нужны
одинаковые CA, ALPN, HTTP-метод, сервер и маршрутизация. Capture должен
успеть записать initial H2 SETTINGS — простого ClientHello недостаточно.
Конкретные CLI-флаги сторонней версии NaiveProxy здесь не выдумываются.

~~~sh
python3 scripts/fingerprint_audit.py \
  --firefox firefox-controlled-page.json \
  --foxtunnel foxtunnel-controlled-page.json \
  --naive naive-controlled-page.json \
  --out stage10-three-way-private.json
~~~

Без настоящего снимка NaiveProxy его TLS/H2-строка остаётся `not_measured`.
Совместимость и результаты работы NaiveProxy из этого не следуют.

## QUIC / HTTP3: схема для будущих наблюдений

Ключи `--firefox-quic`, `--foxtunnel-quic` и `--naive-quic`
принимают **только наблюдения, декодированные на доверенном endpoint**,
в формате ниже. Это **пример формата, не фиктивная запись измерений**:

~~~json
{
  "schema": 1,
  "kind": "h3-quic-observation",
  "capture_method": "endpoint",
  "capture_scenario": "controlled H3 GET, recording original endpoint",
  "quic": {
    "version": 1,
    "tls_alpn": "h3",
    "initial_datagram_size": 1200,
    "transport_parameters": [{"id": 1, "value": 2000}]
  },
  "h3": {"settings": [{"id": 1, "value": 3}]}
}
~~~

**Все числа здесь вымышлены исключительно для иллюстрации формы JSON и не являются захватом.**
Пустые массивы SETTINGS/transport_parameters и неуказанный метод захвата
инструмент теперь отклоняет, чтобы шаблон нельзя было принять за измерение.

Реальные QUIC/H3 transport parameters, TLS внутри QUIC, H3 SETTINGS,
QPACK, управление потоками, packetization, ACK и тайминги нужно измерять
отдельно, при одинаковом контролируемом запросе. Пассивный внешний
наблюдатель не может прочитать зашифрованные H3 SETTINGS без ключей.
Отдельный успешный тест UDP не даёт данных для заполнения этой схемы.

## Что подтверждает этап

Инструмент выполняет воспроизводимое **сравнение имеющихся наблюдений**
и фиксирует, какие именно измерения ещё отсутствуют. Ни одинаковая NSS,
ни совпавший JA3, ни отдельные совпадения SETTINGS не гарантируют сетевую
неотличимость Firefox, превосходство над NaiveProxy или успех обхода DPI.

**Полное тройное сетевое сравнение остаётся незавершённым**, пока не получены
сопоставимые NaiveProxy/Firefox/FoxTunnel захваты, в том числе для H3/QUIC,
и не проверена методика на реальных независимых сетевых путях.

## Реальный замер 20 октября (по времени пользователя), коммит 0f654d8

[CI Stage 10](https://github.com/SawaMEN/FoxTunnel/actions/runs/39327264239)
создал настоящий NSS/H2 ClientHello и начальные фреймы с текущего `update`
на Linux amd64 с pinned NSS 3.130, в сценарии локального HTML GET.

- HTTP/2: **7 совпавших из 7 наблюдаемых полей**; SETTINGS в точном порядке
  `(1,65536),(2,0),(4,131072),(5,16384)`; WINDOW_UPDATE = 12517377.
- TLS: 6 совпали, **6 отличаются**, 1 не наблюдался/не экспортирован.
  Различаются cipher suites, extensions, supported versions,
  signature algorithms, ALPN и JA3. Список supported groups и key shares
  совпал.
- NaiveProxy: TLS/H2 не измерялся; все 13 TLS и 7 H2-проверок —
  `not_measured`.
- QUIC/H3: нет сопоставимых packet/endpoint-assisted captures;
  все 5 полей — `not_measured`.

Данные воспроизводимо сохранены в артефакте CI
`stage10-current-nss-h2-vs-historical-firefox-not-naive`
(не постоянный Release). Сравнение с Firefox — **историческое**,
не одновременная сессия на одном маршруте.
