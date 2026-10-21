package processhost

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A real child executable exercises bounded pipe parsing and process reaping.
func TestMain(m *testing.M) {
	mode := os.Getenv("FOX_PROCESSHOST_FIXTURE")
	if mode == "" {
		os.Exit(m.Run())
	}
	if len(os.Args) > 1 && os.Args[1] == "version" {
		schema := 1
		if mode == "version" {
			schema = 99
		}
		fmt.Printf(`{"schema":1,"product":"protocol-core","integration_schema":1,"sdk_schema":1,"process_schema":%d,"protocol_draft":"foxtunnel-draft-0"}`+"\n", schema)
		return
	}
	if mode == "oversize" {
		fmt.Println(strings.Repeat("x", 5000))
		io.Copy(io.Discard, os.Stdin)
		return
	}
	address := "127.0.0.1:1234"
	if mode == "port" {
		address = "127.0.0.1:"
	}
	if mode == "remote" {
		address = "0.0.0.0:1234"
	}
	fmt.Printf(`{"schema":1,"sequence":1,"type":"ready","role":"client","tcp_listen":%q}`+"\n", address)
	io.Copy(io.Discard, os.Stdin)
	if mode == "stuck" {
		time.Sleep(30 * time.Second)
		return
	}
	sequence := 2
	if mode == "sequence" {
		sequence = 9
	}
	fmt.Printf(`{"schema":1,"sequence":%d,"type":"stopped","role":"client","outcome":"shutdown"}`+"\n", sequence)
}

func TestHostRejectsIncompatibleOrUnboundedRecords(t *testing.T) {
	for _, mode := range []string{"version", "oversize", "remote", "port", "sequence", "stuck"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("FOX_PROCESSHOST_FIXTURE", mode)
			link := filepath.Join(t.TempDir(), "connection.txt")
			os.WriteFile(link, []byte("fixture"), 0600)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			child, err := StartClient(ctx, ClientOptions{Executable: os.Args[0], LinkFile: link})
			if mode == "sequence" || mode == "stuck" {
				if err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				if child.Close() == nil {
					t.Fatal("bad child shutdown accepted")
				}
				if time.Since(start) > 7*time.Second {
					t.Fatal("kill deadline exceeded")
				}
			} else {
				if err == nil {
					child.Close()
					t.Fatal("invalid child accepted")
				}
			}
		})
	}
}
