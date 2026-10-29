package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// CI explicitly holds the SAME destination socket for ten minutes per carrier.
// Ordinary unit runs use two seconds; that is not long-soak evidence.
func TestStage10LongLivedH2H3(t *testing.T) {
	seconds := 2
	if value := os.Getenv("VETROFF_LONG_STREAM_SECONDS"); value != "" {
		var err error
		seconds, err = strconv.Atoi(value)
		if err != nil || seconds < 1 || seconds > 1800 {
			t.Fatal("invalid long-stream duration")
		}
	}
	for _, mode := range []string{"h2-connect", "h3-post"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			var accepts atomic.Int64
			closed := make(chan struct{}, 4)
			target := testDestination(t, func(c net.Conn) {
				accepts.Add(1)
				defer func() { closed <- struct{}{} }()
				_, _ = io.Copy(c, c)
			})
			server := &Server{Username: "alice", Password: "secret", AllowPrivate: true}
			client, addr := testClient(t, server)
			if mode == "h3-post" {
				node := setupEndpoint(t, client, server)
				startNativeH3(t, node, server)
				usePrimary(t, client, node.URL)
			}
			if err := client.SetTransport(mode); err != nil {
				t.Fatal(err)
			}
			client.ConnectTimeout = time.Second
			conn, code := connectSOCKS(t, addr, target)
			if code != 0 {
				t.Fatal("SOCKS setup", code)
			}
			if err := conn.(*net.TCPConn).SetLinger(0); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			deadline := start.Add(time.Duration(seconds) * time.Second)
			var rounds uint64
			for time.Now().Before(deadline) {
				size := 64
				if rounds%2 == 0 {
					size = 32768
				}
				payload := bytes.Repeat([]byte{byte(rounds)}, size)
				binary.BigEndian.PutUint64(payload, rounds)
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, err := conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
					t.Fatal("long-stream integrity", rounds, err)
				}
				rounds++
				time.Sleep(250 * time.Millisecond)
			}
			if accepts.Load() != 1 || rounds < 2 {
				t.Fatal("destination replaced or incomplete exchanges", accepts.Load(), rounds)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("application abort retained destination")
			}
			t.Logf("same destination: elapsed=%s rounds=%d accepts=%d", time.Since(start), rounds, accepts.Load())
		})
	}
}
