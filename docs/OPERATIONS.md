# Эксплуатация

[Главная](../README.md) · [Запуск](START.md) · [Интеграция](INTEGRATION.md)

## Процесс и доступ

Запускайте сервер через службу ОС или супервизор с отдельным пользователем,
лимитами ресурсов и приватным каталогом конфигурации.
Сертификаты, ключи, профили и состояние доступа не должны попадать в `--web-root`.

Для нескольких пользователей задайте вместе `--users-file` и `--users-state`,
исключив одиночные логин/пароль. Формат политики и команды проверки:

```sh
./vetroff access --help
./vetroff server --help
```

Сохраняйте ledger учёта при перезапуске и обновлении. На Linux учёт сохраняется
между запусками. Смену пароля, отключение пользователя и квоты проверяйте
на своей конфигурации. Сервер видит назначения трафика.

Unix SIGINT/SIGTERM останавливают приём и закрывают соединения.
Для переносимого управления процессом используйте `--shutdown-on-stdin-eof`.
На Windows консольный Ctrl+C поддерживается, интеграция с Service Control Manager
не поставляется. Сетевые настройки ОС принадлежат приложению-хосту.

## Сертификаты

VetroffProxy не выпускает и не продлевает сертификаты автоматически.

1. Замените цепочку PEM и ключ по прежним путям, сохранив владельца и права.
2. На Unix отправьте серверу `kill -HUP SERVER_PID` после замены обоих файлов.
3. Проверьте журнал и новое TLS-соединение.

Неверная пара отвергается; остаётся последняя рабочая. Новые handshake используют
новую пару, уже открытые соединения не обрываются. При смене SPKI сначала
обновите pin у клиентов. На Windows выполните контролируемый перезапуск.
SIGHUP также независимо перечитывает access policy; это не общая транзакция
с сертификатом. Остальные изменения конфигурации требуют перезапуска.

## Релизные архивы

С ветки `xfd` формируется **один архив для каждой архитектуры**:

| Target | Архив | Содержимое |
|---|---|---|
| Linux amd64 | `vetroff_VERSION_linux_amd64.tar.gz` | NSS-enabled CLI, `lib/`, `runtime/` (полный Necko), проверяемый manifest |
| Linux arm64 | `vetroff_VERSION_linux_arm64_nss.tar.gz` | NSS CLI, `lib/`, метаданные и лицензии |

Не распаковывайте отдельные старые NSS/Necko архивы поверх единого каталога.
В AMD64-пакете корень после распаковки — `foxtunnel-necko/`, запускайте
`foxtunnel-necko/vetroff`. Сохраняйте все вложенные файлы.
Базовые glibc/libgcc не входят; runtime Linux ориентирован на Ubuntu 24.04.
В ARM64 полный Necko пока недоступен.

Доступные опубликованные версии проверяйте в
[Releases](https://github.com/SawaMEN/FoxTunnel/releases).
[Старые release notes](releases/) описывают только свой тег.

До распаковки и запуска сверяйте SHA-256 и происхождение архива с доверенным
ожидаемым тегом/коммитом. Для выпусков, подписанных основным workflow:

```sh
gh attestation verify "$REVIEWED_ARCHIVE" --repo SawaMEN/VetroffProxy \
  --signer-workflow SawaMEN/VetroffProxy/.github/workflows/release.yml \
  --source-digest "$EXPECTED_COMMIT" --source-ref "$EXPECTED_SOURCE_REF" \
  --deny-self-hosted-runners
```

Переменные задаёт оператор по проверенному выпуску. Source ref —
`refs/heads/main` для запроса версии или `refs/tags/v…` для tag-triggered выпуска.
Старые архивы автоматически подписанными не становятся.
SHA-256 подтверждает целостность относительно доверенной суммы, attestation —
происхождение из workflow. Успешный `version --json` не заменяет эти проверки.

## Установка, обновление и откат

`scripts/deploy_cli.py` управляет пользовательской установкой. Он не меняет
службы ОС, маршруты и конфигурацию. На Unix используйте собственный каталог 0700,
на Windows — закрытый каталог с owner-only ACL.

Пример с заранее проверенными архивом, SHA-256, версией и полным commit:

```sh
python3 scripts/deploy_cli.py --root "$FOXTUNNEL_INSTALL_ROOT" install \
  --archive "$REVIEWED_ARCHIVE" --sha256 "$EXPECTED_SHA256" \
  --version "$EXPECTED_VERSION" --commit "$EXPECTED_COMMIT"
python3 scripts/deploy_cli.py --root "$FOXTUNNEL_INSTALL_ROOT" status
python3 scripts/deploy_cli.py --root "$FOXTUNNEL_INSTALL_ROOT" run -- version --json
```

Для автономной Go-сборки используйте `--binary` вместо `--archive`.
NSS требует полного архива. Установщик проверяет bytes/metadata, создаёт приватную
копию и атомарно переключает активную версию. Прежняя сборка сохраняется.
Уже работающий процесс нужно перезапустить и проверить новым подключением.

```sh
python3 scripts/deploy_cli.py --root "$FOXTUNNEL_INSTALL_ROOT" rollback
python3 scripts/deploy_cli.py --root "$FOXTUNNEL_INSTALL_ROOT" run -- version --json
```

Для восстановления повреждённого состояния есть `recover --release SHA256`.
Повреждение установленного файла блокирует запуск/откат. Конфигурация не мигрируется:
сохраните резервную копию и проверьте её совместимость со старой версией.
Не удаляйте сборки, пока их использует процесс.

## Подготовка выпуска

Основной workflow `release.yml` проверяет Go/NSS, обе архитектуры и состав
архивов. Native pipeline требует повторяемый SHA-256 сборки, H2/H3 payload-тесты,
install/update/rollback и совместимость TCP/H2 с закреплённым прежним alpha.1.
Исходники прежнего выпуска и хеши архивов заданы в
[`release-compat.lock.json`](../scripts/release-compat.lock.json).

`release.py` собирает архив, `release_verify.py` проверяет состав и метаданные,
`release_candidate.py` проверяет кандидат, `release_notes.py` добавляет реальные
размеры и хеши. Publish job подписывает и проверяет provenance перед публикацией.
Обычный push документации не выпускает релиз: нужен явный version request или тег.
Существующие релизы не заменяются.

[Отчёты кандидата](measurements/2026-10-21/releases/provenance.json) описывают
конкретную CI-сборку, не подписывают будущие файлы. Локальные и CI-проверки
не заменяют независимый аудит, полевые испытания или тесты готового VPN-клиента.
