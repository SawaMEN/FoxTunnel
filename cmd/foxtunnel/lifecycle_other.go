//go:build !unix

package main

import (
	"context"
	"os"
	"os/signal"
)

func processContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

// Windows has no SIGHUP. Replace files and restart the process for renewal.
func watchCertificate(func() error) func() { return func() {} }
