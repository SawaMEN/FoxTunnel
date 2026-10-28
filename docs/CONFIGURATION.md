# Параметры и диагностика

[На главную](../README.md) · [Первый запуск](START.md) · [Транспорты](FEATURES.md) · [Разработчику](DEVELOPMENT.md)

Для запуска используйте [единый быстрый старт](START.md). Этот справочник
помогает выбрать источник конфигурации, проверить его и локализовать отказ.
Полный список флагов конкретной сборки выводит сама программа:

```sh
./vetroffproxy version --json
./vetroffproxy setup --help
./vetroffproxy server --help
./vetroffproxy client --help
./vetroffproxy check-config --help
./vetroffproxy doctor --help
```

## Источник настроек

| Вход | Назначение | Проверка до запуска |
|---|---|---|
| `server --config server.json` | Приватный серверный JSON, TLS-файлы и серверная политика | `check-config --config server.json` |
| `client --link-file connection.txt` | Клиентский профиль: серверы, transport, identity и credentials | `check-config --link-file connection.txt` |
| Ручные `client --server …` и флаги | Настройка без профиля; credentials через окружение | `client --help`; offline-команда требует файл |

Профиль владеет настройками протокола. Несовместимые ручные overrides
отклоняются; не смешивайте несколько источников без проверки `--help`.
Серверный JSON, ключ и `connection.txt` являются приватными файлами.

## Проверка без сети

```sh
./vetroffproxy check-config --config server-config/server.json --json
./vetroffproxy check-config --link-file connection.txt --json
./vetroffproxy check-config --link-file connection.txt --ca-cert ca.pem --json
```

Команда не открывает listener, не разрешает DNS и не подключается к серверу.
Она проверяет файл, совместимость настроек/сборки и локальные TLS-материалы.
`--config` и `--link-file` взаимоисключающие; stdin не поддерживается.
`--engine mozilla` и `--ca-cert` относятся только к клиентскому профилю.
JSON schema 1 содержит фиксированные коды проверки, без путей и credentials.
Успех — exit code 0; ошибка — ненулевой код. Offline-успех не проверяет сеть.

## Проверка соединения

`doctor` требует доступный через сервер **ваш echo-сервис**, который вернёт
полученные байты. Обычный HTTP/TLS-сайт для этой проверки не подходит.
Замените адрес ниже адресом своего echo-сервиса, разрешённым server policy:

```sh
./vetroffproxy doctor --link-file connection.txt --target echo.example.net:9000 --json
./vetroffproxy doctor --link-file connection.txt --target echo.example.net:9000 --network udp --timeout 15s --json
```

Probe отправляет 32 случайных байта и проверяет точный ответ. UDP требует
соответствующего разрешения на обеих сторонах. `--server-index 0` выбирает
одну запись профиля (0–7), без balancing/bond. Timeout — 100ms–2m, по
умолчанию 15s. Транспорт и trust берутся из профиля; `--ca-cert` добавляет CA,
`--engine mozilla` требует native-сборку. JSON schema 1 содержит этап,
ограниченный reason и длительность; адреса и секреты в него не включаются.

При ошибке проверяйте последний неуспешный этап: локальную конфигурацию,
DNS/TCP или UDP-доступность, TLS/SNI/CA/pin, авторизацию, protocol policy,
разрешение назначения и echo. Ошибка trust не разрешает H3→H2 downgrade.

## Протокол, backend и наблюдение

| Параметр | Поведение |
|---|---|
| `--protocol-policy legacy` | Совместимая политика по умолчанию; отличается от выбора engine |
| `--protocol-policy strict` | Явное согласование версии/capabilities на обеих сторонах; без bond/discovery |
| `--engine legacy` | Выбор существующих backend-настроек; не отключение проверки TLS |
| `--engine mozilla` | NSS для TCP и Neqo для поддерживаемого H3; нужен подходящий native bundle |
| `--h2-receive-profile firefox-158` | Измеренные H2 receive settings для поддерживаемого H2/XHTTP |
| `--tls-client-profile firefox-158` | Socket-local NSS TLS profile; требует NSS 3.130 |
| `--engine-status-interval 10s` | Периодический локальный JSON состояния; по умолчанию выключен |

`setup --protocol-policy strict` создаёт прямой профиль одного узла.
Профиль переносит policy на клиент; подробный формат —
[wire negotiation](reference/WIRE-NEGOTIATION.md). SDK предоставляет `Status()`
и `NotifyNetworkChange()`; настройка и lifecycle описаны в
[руководстве разработчика](DEVELOPMENT.md).

Session resumption NSS/Neqo, повторная проверка trust, границы 0-RTT и памяти
описаны в [исправлениях native-адаптеров](UPDATE-FIXES.md).
Остановка, сертификаты, обновление/откат — в [эксплуатации](OPERATIONS.md).
