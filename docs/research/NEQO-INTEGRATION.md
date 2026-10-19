# Neqo / HTTP3: экспериментальный клиент

**Русский** | [English](NEQO-INTEGRATION.en.md)

Четвёртый этап добавляет настоящий Mozilla Neqo 0.33.0 через Rust staticlib и
версионированный C ABI 1. Первый проверяемый target — **Linux amd64**. Сервер
остаётся прежним Go/quic-go сервером FoxTunnel; экспериментальный сервер Neqo
не переносится в production. Обычный `h3-post` по умолчанию использует quic-go.
Публичная матрица Linux amd64/arm64 NSS не меняется и не включает этот backend.

## Сборка

Нужны Go 1.26.9, Rust **1.99.1** с rustfmt/clippy, Python 3.11+, git, gcc/g++,
pkg-config, libclang, binutils, unzip и dpkg-deb. В Ubuntu 24.04:

```sh
sudo apt-get install build-essential pkg-config libclang-dev git binutils unzip python3
rustup toolchain install 1.99.1 --profile minimal --component rustfmt,clippy
python3 scripts/build_neqo.py
source rust/neqo-bridge/target/foxtunnel-build/env.sh
go build -tags nss,neqo -o foxtunnel-neqo ./cmd/foxtunnel
./foxtunnel-neqo version --json
```

Скрипт использует `scripts/neqo.lock.json` и `Cargo.lock`: Neqo
`1ec4c2a3ccd7ada264112d1b70b070381557d844`, nss-rs
`ba8a3f6acffc7e25749054969ccbbb3ca615df7f`, исходники заголовков NSS 3.130
и hash-pinned заголовки NSPR 4.39. Неизменённые NSS/NSPR-библиотеки берутся из
закреплённого Firefox 158.0 через существующий Mozilla lock с проверкой SHA-256.
Системная старая NSS не подменяет этот runtime. Заголовок `build_stamp.h` содержит
хеш Rust-архива и предотвращает повторное использование устаревшего cgo-кэша.
Скрипт сохраняет provenance и тексты лицензий Rust-зависимостей; всё это только
сборочные действия. Работающий клиент ничего не скачивает и не запускает helper.

`version --json` дополнительно показывает `quic_backends`, `neqo_version` и
`neqo_revision`. Отсутствие поддержки, другой ABI или NSS runtime — ошибка,
а не тихий переход на quic-go. Обычные release workflow не собирают Neqo.

## Включение и fallback

```sh
foxtunnel-neqo client --server https://proxy.example --transport h3-post \
  --quic-backend neqo --tls-backend auto
```

При необходимости разрешить переход на H2:

```sh
foxtunnel-neqo client --server https://proxy.example --transport h3-post \
  --quic-backend neqo --h3-fallback h2 --quic-handshake-timeout 2s
```

Учётные данные задаются прежними переменными окружения. Сервер должен
обслуживать UDP и TCP на одном адресе/порту, иметь действительный сертификат
и существующую авторизацию FoxTunnel. Возможен `--tls-backend nss`;
`--tls-backend go` с Neqo отклоняется. Без `--h3-fallback h2` перехода на H2 нет.
Бюджет Neqo по умолчанию 2 с, допустимы 100 мс–10 с. Общий `--connect-timeout`
ограничивает обе попытки вместе, но не срок жизни открытого потока.

Переход допустим только после сетевой недоступности/таймаута **рукопожатия**, до
создания HTTP-потока. Тело запроса к этому моменту не прочитано. Ошибки CA/SNI/pin,
ALPN/протокола, конфигурации, отмена и HTTP-статусы не разрешают fallback.
После успешной проверки H3 нет повторной отправки запроса по H2 даже при обрыве.
После сетевого отказа выбор H2 запоминается на 30 с отдельно для origin и TLS
политики; после этого возможна новая проба UDP. H2 использует тот же URL, CA,
SNI, дополнительный pin и TLS 1.3 через NSS; редиректы не выполняются.

Параметры `--quic-backend`, `--h3-fallback`, `--quic-handshake-timeout` локальны:
они не добавляются в ссылку, setup и серверный JSON. С H3-ссылкой:

```sh
foxtunnel-neqo client --link-file connection.txt --quic-backend neqo --h3-fallback h2
```

Ссылка уже должна выбирать `h3-post` и auto/nss; она сама не включает Neqo.
SDK: `ClientConfig{Transport:"h3-post", QUICBackend:"neqo", H3Fallback:"h2",
QUICHandshakeTimeout:2*time.Second}` с прежними CA/ServerName/SPKIPin.
Профили TCP `--tls-client-profile firefox-158` и H2 receive profile с Neqo не
принимаются: настройки браузера TCP нельзя выдавать за настройки QUIC.

## Границы ABI и ресурсов

Go actor закрепляет OS thread; только он вызывает Rust, включая создание и
освобождение состояния. Rust/Rc-структуры не перемещаются между потоками, Go
указатели не сохраняются Rust. Паника Rust перехватывается на ABI-границе.
UDP принадлежит Go; закрытие соединения посылает QUIC close, закрывает сокет,
завершает приём и только затем освобождает engine. Нет sidecar/браузерного процесса.

На транспорт — до восьми origin, на соединение — до 32 активных запросов.
Очередь команд — 64, UDP — восемь datagram, upload — одна запись 32 КиБ на запрос.
Ответ читается прямо в буфер вызывающего кода; отмена завершает обработку до
его повторного использования. Окно QUIC соединения 1 МиБ, локального bidi-потока
128 КиБ; входящие bidi запрещены, uni ограничены восемью. Выходные очереди и
QPACK дополнительно ограничиваются Neqo. Неожидаемые/крупные метаданные отклоняются:
заголовки до 64 КиБ и 128 request fields, цепочка сертификатов до 1 МиБ/16 cert.
Эти величины не являются полной оценкой native-памяти NSS или всего процесса.

Нет 0-RTT, cache resumption tokens, ECH, миграции UDP-адреса или объявления
WebTransport/HTTP datagrams ради отпечатка. Сертификат проверяется через ту же
Go x509 CA/hostname/SPKI политику до `authenticated` и создания запроса. Полного
Necko/Firefox lifecycle, соответствия отпечатка Firefox и превосходства над
NaiveProxy/TSPU эти изменения не устанавливают.

## Проверки

Независимый Go HTTP3-сервер проверяет большие данные, четыре параллельных потока,
reuse/cold handshake без resumption, CA/SNI/pin до HTTP, неверный ALPN и отмену.
Отдельные тесты настоящего SOCKS/публичного SDK проверяют pin, 2 МиБ, half-close,
жизнь после отмены setup-контекста и реальный NSS H2 fallback. Смешивания ключей,
origin/SNI/pin при перестройке пулов не добавлено.

UDP-стенд теряет **настоящие QUIC datagram**: по 5 мс в каждую сторону и каждый
17-й пакет в каждом направлении. Другой тест отбрасывает все UDP-пакеты и проверяет
150-мс handshake budget с включённым/выключенным fallback. Это userspace loopback,
не операторская сеть, не измерение независимой полосы и не DPI-испытание.
[Команды и сохранённые результаты](../measurements/2026-10-19/neqo/README.md).

Отдельный workflow `Mozilla Neqo client experiment` собирает pinned runtime,
проверяет Rust fmt/clippy/tests, Go vet/race, SDK, trust/fallback и metadata.
Долгие нагрузки/native sanitizer, остальные ОС/arm64, полный browser fingerprint
и независимый внешний аудит остаются последующими проверками.

Источники: [Neqo v0.33.0](https://github.com/mozilla/neqo/tree/1ec4c2a3ccd7ada264112d1b70b070381557d844),
[nss-rs](https://github.com/mozilla/nss-rs/tree/ba8a3f6acffc7e25749054969ccbbb3ca615df7f),
[HTTP3 в Firefox](https://firefox-source-docs.mozilla.org/networking/http/http3.html).
