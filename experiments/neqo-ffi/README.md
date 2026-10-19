# Mozilla Neqo — начальный Rust/C ABI прототип

Это **настоящий** `neqo-http3` клиент, создающий QUIC v1 Initial через NSS, но **не рабочий HTTP/3-прокси**. Никакие пакеты сервера здесь не принимаются; аутентификация сертификатов, TLS pin, потоки запросов, UDP event loop, cancellation, Go bridge и HTTP/3 POST ещё не реализованы. Нельзя использовать модуль для продакшена или обхода блокировок.

## Источники

* Neqo: `ad7d629eaa67ab16e42e704a51f59fb14bdffb1e` ([репозиторий](https://github.com/mozilla/neqo)).
* NSS берётся через `nss-rs` из рабочего набора зависимостей Neqo; точная фиксация дополнительных зависимостей осуществляется через Cargo.lock после валидации CI.
* Rust >= 1.90, Linux, NSS/NSPR dev и системный C компилятор. Код Rust/C ABI не входит в публичные архивы FoxTunnel.

## Локальная проверка

```sh
sudo apt-get install libnss3-dev libnspr4-dev pkg-config build-essential
cd experiments/neqo-ffi
cargo test
cargo build
cc -std=c11 -Wall -Wextra -Werror test_bridge.c -L target/debug \
  -lfoxtunnel_neqo -Wl,-rpath,"$PWD/target/debug" -o target/debug/neqo-abi-test
./target/debug/neqo-abi-test
```

ABI: `ft_neqo_abi_version` = 1; `ft_neqo_new` валидирует SNI, адреса и NSS, `ft_neqo_initial` возвращает готовый Neqo Initial и не теряет его при маленьком буфере; `ft_neqo_free` освобождает ресурсы. Указатели живут только на стороне Rust, из Go в Rust не передаются Go-указатели. Handle принадлежит одному потоку; вызывающий обязан сериализовать вызовы.

Следующие этапы — отдельный безопасный UDP драйвер, проверка сертификатов и SPKI pin до любого HTTP Authorization, HTTP/3 stream API, закрытие/таймеры и CI-интероперабельность с Go H3 сервером. До этого штатный H3 в FoxTunnel остаётся на `quic-go`. См. [исследовательский план](../../docs/research/NEQO-INTEGRATION.md).
