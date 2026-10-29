package processhost

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A real child executable exercises bounded pipe parsing and process reaping.
func TestMain(m *testing.M) {
	mode := os.Getenv("VETROFFTEST_PROCESSHOST_FIXTURE")
	if mode == "" {
		os.Exit(m.Run())
	}
	if mode == "pipe-holder" {
		time.Sleep(12 * time.Second)
		return
	}
	holdPipe := func() {
		child := exec.Command(os.Args[0])
		child.Env = append(os.Environ(), "VETROFFTEST_PROCESSHOST_FIXTURE=pipe-holder")
		child.Stdout = os.Stdout
		if err := child.Start(); err != nil {
			os.Exit(9)
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "version" {
		schema := 1
		if mode == "version" {
			schema = 99
		}
		fmt.Printf(`{"schema":1,"product":"protocol-core","integration_schema":1,"sdk_schema":1,"process_schema":%d,"protocol_draft":"vetroff-draft-0"}`+"\n", schema)
		if mode == "version-descendant" {
			holdPipe()
		}
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
	if mode == "shutdown-descendant" {
		holdPipe()
		time.Sleep(30 * time.Second)
		return
	}
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
			t.Setenv("VETROFFTEST_PROCESSHOST_FIXTURE", mode)
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

func TestAuditVersionChildCannotRetainStartupPipe(t *testing.T) {
	t.Setenv("VETROFFTEST_PROCESSHOST_FIXTURE", "version-descendant")
	file := filepath.Join(t.TempDir(), "link")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	child, err := StartClient(ctx, ClientOptions{Executable: os.Args[0], LinkFile: file})
	if child != nil {
		child.Close()
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("version timeout failed to bound inherited stdout pipe")
	}
	if err == nil {
		t.Fatal("version child with retained pipe unexpectedly accepted")
	}
}
func TestAuditShutdownClosesDescendantHeldOutput(t *testing.T) {
	t.Setenv("VETROFFTEST_PROCESSHOST_FIXTURE", "shutdown-descendant")
	file := filepath.Join(t.TempDir(), "link")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	child, err := StartClient(ctx, ClientOptions{Executable: os.Args[0], LinkFile: file})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = child.Close()
	if time.Since(start) > 7*time.Second {
		t.Fatal("shutdown was held beyond kill budget by inherited output pipe")
	}
	if err == nil {
		t.Fatal("stuck child reported clean shutdown")
	}
}
