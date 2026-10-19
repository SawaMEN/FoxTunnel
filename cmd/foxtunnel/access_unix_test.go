//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"github.com/SawaMEN/FoxTunnel/internal/access"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type safeLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeLog) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *safeLog) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
func awaitSignal(t *testing.T, f func() bool) {
	t.Helper()
	until := time.Now().Add(time.Second)
	for !f() {
		if time.Now().After(until) {
			t.Fatal("signal handler did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestAccessSignalsReloadTransactionallyAndRedactLogs(t *testing.T) {
	file := cliPolicyFile(t)
	d, err := access.ReadDocument(file)
	if err != nil {
		t.Fatal(err)
	}
	c, err := access.New(d, "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sink := new(safeLog)
	old := log.Writer()
	log.SetOutput(sink)
	defer log.SetOutput(old)
	stop := watchAccess(c, file, false)
	defer stop()
	d.Users[0].Disabled = true
	data, _ := json.Marshal(d)
	os.WriteFile(file, data, 0600)
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, func() bool { return c.Snapshot().Users[0].Disabled })
	os.WriteFile(file, []byte(`{"v":1,"users":[],"secret":"`+cliSecret+`"}`), 0600)
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	awaitSignal(t, func() bool { return strings.Contains(sink.String(), "reload rejected") })
	if !c.Snapshot().Users[0].Disabled {
		t.Fatal("bad reload replaced policy")
	}
	syscall.Kill(os.Getpid(), syscall.SIGUSR1)
	awaitSignal(t, func() bool { return strings.Contains(sink.String(), "access statistics") })
	if strings.Contains(sink.String(), cliSecret) || strings.Contains(sink.String(), "private-username") {
		t.Fatal("logs exposed credentials")
	}
}
