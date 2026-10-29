//go:build unix

package main

import (
	"encoding/json"
	"github.com/SawaMEN/VetroffProxy/internal/access"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func watchAccess(c *access.Controller, path string, relay bool) func() {
	signals := make(chan os.Signal, 1)
	done := make(chan struct{})
	finished := make(chan struct{})
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGUSR1)
	go func() {
		defer close(finished)
		for {
			select {
			case <-done:
				return
			case sig := <-signals:
				if sig == syscall.SIGUSR1 {
					data, _ := json.Marshal(c.Snapshot())
					log.Printf("access statistics: %s", data)
					continue
				}
				d, err := readAccessPolicy(path, relay)
				if err == nil {
					err = c.Replace(d)
				}
				if err != nil {
					log.Print("access reload rejected; previous policy retained")
				} else {
					log.Print("access policy reloaded")
				}
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { signal.Stop(signals); close(done); <-finished }) }
}
