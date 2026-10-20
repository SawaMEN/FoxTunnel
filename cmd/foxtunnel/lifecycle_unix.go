//go:build unix

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func processContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func watchCertificate(reload func() error) func() {
	signals := make(chan os.Signal, 1)
	done, finished := make(chan struct{}), make(chan struct{})
	signal.Notify(signals, syscall.SIGHUP)
	go func() {
		defer close(finished)
		for {
			select {
			case <-done:
				return
			case <-signals:
				if err := reload(); err != nil {
					log.Print("TLS certificate reload rejected; previous certificate retained")
				} else {
					log.Print("TLS certificate reloaded for new handshakes")
				}
			}
		}
	}()
	return func() { signal.Stop(signals); close(done); <-finished }
}
