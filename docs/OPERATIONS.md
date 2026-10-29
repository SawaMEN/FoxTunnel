# Эксплуатация

[Документация](README.md) · [Запуск](START.md)

## Доступ и процесс

Запускайте сервер через службу ОС с отдельным пользователем и приватным каталогом.
Ключи, профили и ledger не должны попадать в `--web-root`.
Для нескольких пользователей задайте вместе `--users-file` и `--users-state`,
исключив одиночные credentials. Формат и команды — `./vetroff access --help`.
Сохраняйте ledger учёта при обновлении.

SIGINT/SIGTERM останавливают процесс; переносимый вариант — `--shutdown-on-stdin-eof`.
После замены обоих PEM-файлов `kill -HUP SERVER_PID` перечитывает сертификат и access policy.
Неверная пара сертификат/ключ не заменяет рабочую. При смене SPKI обновите pin клиентов.
На Windows перезапустите процесс. Остальные настройки требуют перезапуска.

## Архивы и проверка

Linux AMD64 и ARM64: `vetroff_VERSION_linux_ARCH.tar.gz`, CLI с NSS и полный Necko.
Храните весь каталог `vetroff-necko/`, включая `lib/`, `runtime/` и метаданные.
Базовая среда — Ubuntu 24.04. Доступные файлы — в [Releases](https://github.com/SawaMEN/VetroffProxy/releases).

Сверьте доверенную SHA-256 и provenance до запуска. Для подписанного workflow-архива:

```sh
gh attestation verify "$REVIEWED_ARCHIVE" --repo SawaMEN/VetroffProxy \
  --signer-workflow SawaMEN/VetroffProxy/.github/workflows/release.yml \
  --source-digest "$EXPECTED_COMMIT" --source-ref "$EXPECTED_SOURCE_REF" \
  --deny-self-hosted-runners
```

Ожидаемые значения берутся из проверенного выпуска. Source ref: `refs/heads/main`
для version request или `refs/tags/v…` для выпуска по тегу. `version --json` не проверяет provenance.

## Обновление и откат

В собственном приватном каталоге:

```sh
python3 scripts/deploy_cli.py --root "$INSTALL_ROOT" install \
  --archive "$REVIEWED_ARCHIVE" --sha256 "$EXPECTED_SHA256" \
  --version "$EXPECTED_VERSION" --commit "$EXPECTED_COMMIT"
python3 scripts/deploy_cli.py --root "$INSTALL_ROOT" run -- version --json
python3 scripts/deploy_cli.py --root "$INSTALL_ROOT" rollback
```

Для автономной Go-сборки вместо `--archive` используйте `--binary`.
Установщик не меняет службы, сеть или конфигурацию. Перезапустите работающий процесс
после смены активной версии; сохраните резервную копию конфигурации и ledger.
Повреждение файлов блокирует запуск. Остальные команды — `python3 scripts/deploy_cli.py --help`.
