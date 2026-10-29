module example.com/independent-vetroff-consumer

go 1.26.10

require (
	github.com/SawaMEN/VetroffProxy v0.0.0
	github.com/quic-go/quic-go v0.64.0
)

require (
	github.com/coder/websocket v1.8.15 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/SawaMEN/VetroffProxy => ../..
