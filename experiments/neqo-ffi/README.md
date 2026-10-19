# Mozilla Neqo — UDP/event-loop эксперимент (Rust/C ABI v2)

Рабочая реализация FoxTunnel H3 остаётся на `quic-go`. Этот прототип использует настоящий Mozilla Neqo и NSS для QUIC, умеет посылать/принимать UDP, обслуживать таймеры и **безусловно отклоняет непроверенные сертификаты**. Он **не является готовым HTTP/3-туннелем**: проверка CA/SPKI, авторизация, HTTP/3 stream API и интеграция с Go-клиентом ещё не реализованы.

## Зависимости и проверка

- Neqo: коммит `ad7d629eaa67ab16e42e704a51f59fb14bdffb1e`.
- nss-rs: `ba8a3f6acffc7e25749054969ccbbb3ca615df7f`, совместимый с зафиксированным Neqo. Полная фиксация в `Cargo.lock`.
- Rust 1.90.0, NSS 3.126 + NSPR из проверенного Mozilla release (системной NSS 3.98 Ubuntu 24.04 недостаточно).
- Linux amd64 — первый тестируемый вариант. Не включено в релизный workflow.

Локально с заранее установленными совместимыми библиотеками NSS:

```sh
cd experiments/neqo-ffi
cargo test --locked
cargo build --locked
cc -std=c11 -Wall -Wextra -Werror test_bridge.c -L target/debug \
  -lfoxtunnel_neqo -Wl,-rpath,"$PWD/target/debug" -o target/debug/neqo-abi-test
./target/debug/neqo-abi-test
```

Для активной проверки UDP с тестовым HTTP/3-сервером из исходников FoxTunnel:

```sh
# Из корня репозитория; нужен Go 1.26 и сборка Rust cdylib выше
go build -o /tmp/neqo-h3-fixture ./experiments/neqo-ffi/cmd/h3-fixture
cc -std=c11 -Wall -Wextra -Werror experiments/neqo-ffi/probe_udp.c \
  -I experiments/neqo-ffi -L experiments/neqo-ffi/target/debug \
  -lfoxtunnel_neqo -Wl,-rpath,"$PWD/experiments/neqo-ffi/target/debug" -o /tmp/neqo-udp-probe
/tmp/neqo-h3-fixture > /tmp/neqo-port.txt &
/tmp/neqo-udp-probe 127.0.0.1 "$(cat /tmp/neqo-port.txt)" example.org
```

Этот тест ожидает **отказ в TLS-аутентификации** при подключении к самоподписанному сертификату: успешный exit code означает, что сервер был достигнут, а его сертификат **отклонён**, не принят. Никаких HTTP/3-запросов и учётных данных тест не отправляет.

## ABI v2 и гарантии

- `ft_neqo_new`: отдельный Neqo HTTP/3-клиент, числовые локальный/удалённый UDP адреса, обязательный SNI.
- `ft_neqo_next`: возвращает датаграмму (1), задержку таймера (2), отсутствие действий (0) или код ошибки. При маленьком буфере пакет сохраняется для повторного чтения.
- `ft_neqo_feed`: принимает UDP-датаграмму только от ранее заданного адреса. C/Go-вызывающий должен использовать connected UDP socket либо проверять source из `recvfrom`; передаваемая строка не заменяет проверку настоящего отправителя.
- `ft_neqo_auth_rejected`: сообщает о запрете TLS-аутентификации; состояния «сертификат принят» **нет**.
- `ft_neqo_stop`, `ft_neqo_free`: остановка и освобождение ресурсов, только одним потоком.
- `ft_neqo_initial`: совместимый с ABI v1 путь для получения первого пакета; не обрабатывает обратный трафик и таймеры.

Neqo сам не управляет UDP-сокетом. Код Go не должен передавать Go-указатели в хранимые Rust-структуры. Сетевые операции, обработку таймеров, отмены и close нужно сериализовать одним владельцем. В этой версии не реализована реальная проверка доверия, поэтому **даже верный сертификат будет отклонён** — это защита от ошибочного разрешения трафика до реализации CA/SPKI.

Следующий этап: полноценная проверка цепочки X.509 и SPKI pin по заданной политике доверия, затем HTTP/3-запросы и обратно совместимая привязка к Go-клиенту. См. [исследовательский план](../../docs/research/NEQO-INTEGRATION.md).
