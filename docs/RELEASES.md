# Релизные кандидаты — этап 9 из 10

Все изменения этапов 1–7 включены в main через PR #43, merge `3292c9ac`.
Интеграции Hiddify/3x-ui этапа 8 отложены по указанию пользователя.
Этот этап проверяет упаковку и эксплуатацию самостоятельного protocol core.
Он не закрывает защиту main, независимый аудит безопасности или host VPN.

## Состав и платформы

Стандартная схема поставки содержит ровно два runtime-архива:

| Target | Archive | Native verification |
|---|---|---|
| Linux amd64, NSS | `foxtunnel_VERSION_linux_amd64_nss.tar.gz` | Ubuntu 24.04 amd64 |
| Linux arm64, NSS | `foxtunnel_VERSION_linux_arm64_nss.tar.gz` | Ubuntu 24.04 arm64 |

Внутри — executable, полный `lib/`, build/integration metadata, сведения об
источниках Mozilla runtime и лицензии. SDK/process schemas 1/1 и wire draft 0
проверяются отдельно от release tag. Runtime содержит NSS для TCP/H2 и quic-go
для H3. Экспериментальный Neqo/Mozilla bundle остаётся отдельным pipeline.
Native Go SDK на macOS/Windows не является сертификатом runtime-архивов для
этих ОС. APK, DMG, native Swift/JNI packages и системные установщики не добавляются.

`release.py` проверяет чистый checkout, фактические version/commit/platform/
compiler/backend/schema, загруженный NSS и `$ORIGIN/lib` RPATH. Verifier
требует native smoke pass, разрешённый состав, ожидаемые metadata, bounded
JSON/files и hash каждой bundled library; links/special files отвергаются.
Архив не должен содержать private config, ключи, profiles, measurement tools
или source tree. Базовые glibc/libgcc не входят в bundle; baseline указан в metadata.

## Native pipeline

На каждой из двух архитектур CI выполняет:

1. Сборку основного NSS candidate и запуск actual `version --json`.
2. Повторную сборку того же source/version с отдельными GOCACHE/GOTMPDIR.
   SHA-256 полных архивов должен совпасть. Epoch фиксирован source commit.
3. Сборку второй лабораторной версии того же source для проверки смены слотов.
4. Install → update → rollback в новом private deployment root.
5. После каждой активации — настоящий installed CLI, H2 через bundled NSS,
   H3 через quic-go, проверяемый payload, EOF shutdown, reap и освобождение порта.
6. Проверку сохранения private config bytes/mode и правильного active identity.
7. Совместимость с закреплённым опубликованным alpha.1 и строгие отказы.

Повторяемость относится к одному native runner, source и зафиксированному
toolchain; это не независимое воспроизведение другим оператором или на другой
ОС. Лабораторная update-версия отличается tag/build metadata, а не протокольным
кодом; реальная межверсионная wire-проверка выполняется отдельно с alpha.1.
SHA-256 всего NSS archive охватывает executable, libs, metadata и notices.

`release_candidate.py` принимает primary/replica/upgrade archives и доверенные
expected version/commit. Он проверяет архивы до выполнения, затем использует
существующий deployment manager с private staging, file hashes, блокировкой и
атомарной сменой activation state. Установки и тестовые секреты удаляются с
временным каталогом. Системные службы, маршруты и пользовательские конфигурации
не меняются. Отчёт содержит только идентичности, агрегаты и hashes go-test events;
raw logs/профили/ключи не сохраняются в CI artifact.

## Опубликованный предыдущий стандартный выпуск

[`release-compat.lock.json`](../scripts/release-compat.lock.json) закрепляет
реальные Linux Go archives `v0.1.0-alpha.1`: URL, полный размер, SHA-256 и source
commit `f491e0e9`. Это прежний стандартный выпуск для обеих архитектур;
экспериментальный alpha.2 Mozilla/Neqo не входит в эту матрицу.
Загрузка ограничена размером, hash проверяется до извлечения/запуска. Из архива
извлекается только обычный executable в private temp folder. Его фактические
tag/commit/platform/flavor/draft проверяются перед loopback-тестом.

Проверяются old-client/new-server и new-client/old-server TCP/H2, а также
отказ старому клиенту при строгом новом сервере и отказ строгого нового клиента
старому серверу. Legacy binary не устанавливается в deployment slots и не
предлагается пользователю как обновление. Эта матрица не сертифицирует все
исторические теги, NSS/Neqo engine combinations, UDP или экспериментальные
расширения между произвольными версиями.

## SHA-256 и подписанное происхождение

В release assets остаются два runtime-архива. `release_notes.py` сначала
выполняет offline verification обоих архивов, затем добавляет в release notes
точный commit, имена, размеры и SHA-256. Не требуются дополнительные index,
manifest или checksum assets. Заметки формируются из реально проверенных bytes,
а не из заранее написанных сумм. Локально вывод notes создаётся новым private file.

SHA-256 подтверждает целостность относительно доверенной ожидаемой суммы;
он не является подписью. До публичной загрузки publish job подписывает GitHub
artifact attestations точных архивов и проверяет repository, workflow, source
commit/ref и запрет self-hosted runner. Релиз зависит от quality, Go/NSS
govulncheck, обеих native bundle jobs и complete archive-set verification.

Перед запуском скачанного executable:

- Получите ожидаемые tag, полный commit и SHA-256 из доверенного источника.
- Сверьте bytes/hash и offline archive metadata/content.
- Проверьте GitHub attestation точного файла с ожидаемыми repo, workflow,
  commit и source ref. Для version request это `refs/heads/main`, для tag push —
  соответствующий `refs/tags/...`; выбирайте ref по происхождению выпуска.
- Сохраните полный bundle вместе с `lib/` и прежнюю установку для rollback.

`gh attestation verify` должен использовать signer workflow
`SawaMEN/FoxTunnel/.github/workflows/release.yml`, repo `SawaMEN/FoxTunnel`,
`--source-digest` с ожидаемым полным SHA, ожидаемый `--source-ref` и
`--deny-self-hosted-runners`. Успешный `version --json` сам по себе не является
проверкой подписи: запускайте executable только после проверки provenance.

Обычный merge и PR не публикуют release. Сохраняется одноразовый explicit
version request/tag gate, запрет замены существующего release/tag и prerelease
статус. Подписанное публичное происхождение конкретного будущего релиза должно
проверяться на его фактическом файле; лабораторный отчёт его не подменяет.
