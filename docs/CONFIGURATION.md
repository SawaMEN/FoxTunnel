# Диагностика

[Документация](README.md) · [Запуск](START.md)

## Проверка без сети

```sh
./vetroff version --json
./vetroff check-config --config server-config/server.json --json
./vetroff check-config --link-file connection.txt --json
```

`--config` и `--link-file` взаимоисключающие. Проверка читает конфигурацию и локальные
TLS-файлы, но не подключается к серверу. Успех — код 0; ошибка — ненулевой код.
Профиль задаёт настройки протокола: несовместимые ручные overrides отклоняются.
Для своего CA добавьте `--ca-cert ca.pem`, сохраняя проверку имени сертификата.

## Проверка соединения

`doctor` требует **ваш echo-сервис**, который возвращает полученные байты.
Обычный сайт для этой команды не подходит.

```sh
./vetroff doctor --link-file connection.txt --target echo.example.net:9000 --json
./vetroff doctor --link-file connection.txt --target echo.example.net:9000 --network udp --json
```

Для UDP он должен быть разрешён на обеих сторонах. `--server-index` проверяет
отдельную ноду; `--timeout` ограничивает ожидание. Ошибка trust не разрешает downgrade.

| Ошибка | Проверить |
|---|---|
| Нет подключения | DNS, TCP/UDP-порт, firewall, процесс сервера |
| TLS | Домен/SNI, срок и цепочку сертификата, CA и pin |
| Авторизация | Профиль и актуальность пароля |
| Нет трафика | SOCKS5 и DNS в приложении, server policy, назначение |
| Нет native backend | Возможности сборки в `version --json` |

Все флаги: `./vetroff COMMAND --help`. Локальное состояние можно включить
через `--engine-status-interval 10s`; вывод JSON не содержит паролей.
