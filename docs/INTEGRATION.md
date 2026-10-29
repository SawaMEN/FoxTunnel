# Go SDK и отдельный процесс

[Документация](README.md) · [Полный контракт API](reference/SDK.md)

Go-модуль — `github.com/SawaMEN/VetroffProxy`, пакет — `vetroff`.
Закрепляйте проверенный тег/коммит. TUN, маршрутизация и DNS принадлежат приложению-хосту.

## Go

```go
client, err := vetroff.NewClient(vetroff.ClientConfig{
    ServerURL: "https://vpn.example.com",
    Credentials: vetroff.Credentials{Username: "user", Password: secret},
})
if err != nil { return err }
defer client.Close()
conn, err := client.DialContext(ctx, "tcp", "example.com:443")
if err != nil { return err }
defer conn.Close()
```

Примеры: [клиент](../examples/embed/main.go), [управление процессом](../examples/process-host/main.go).
`NewServer` возвращает HTTP handler; TLS/listeners и остановку обслуживает хост.
UDP: `ExchangeUDP` — запрос/ответ, `OpenUDP` — постоянная ассоциация.
Состояние: `Status`, `Snapshot`, `WatchStatus`; смена сети: `NotifyNetworkChange`.
Закрывайте соединения/ассоциации. После неоднозначного сетевого сбоя данные не переигрываются.

## Отдельный процесс

```sh
./vetroff client --link-file /private/connection.txt \
  --listen 127.0.0.1:1080 --events-json --shutdown-on-stdin-eof
```

`processhost.StartClient` управляет дочерним процессом; native-библиотеки остаются вне хоста.
Профиль — приватный обычный файл. Читайте stdout непрерывно: это JSON Lines событий;
диагностика идёт в stderr. `ready` подтверждает локальный bind, а не доступ к интернету.
Закрытие stdin запрашивает остановку; после завершения дождитесь выхода процесса.

Схемы, UDP-лимиты, lifecycle, ошибки и обязанности хоста — в [SDK-контракте](reference/SDK.md).
Имена `VETROFF_*`, `vetroff://` и wire identifiers используются без прежних алиасов.
