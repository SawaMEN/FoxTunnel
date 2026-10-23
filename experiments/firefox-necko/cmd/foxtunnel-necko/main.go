// Separate opt-in launcher. Does not change the ordinary FoxTunnel CLI or SDK.
package main

import (
	"context"
	"flag"
	"fmt"
	firefox "github.com/SawaMEN/FoxTunnel/experiments/firefox-necko"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func main() {
	executable, e := os.Executable()
	if e != nil {
		fmt.Fprintln(os.Stderr, "cannot locate launcher")
		os.Exit(1)
	}
	bundle := flag.String("bundle", filepath.Dir(executable), "verified bundle directory")
	config := flag.String("config", "", "private JSON configuration file")
	verify := flag.Bool("verify", false, "verify bundle and exit")
	flag.Parse()
	if *verify {
		if _, e := firefox.VerifyBundle(*bundle); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		fmt.Println("Firefox bundle verified")
		return
	}
	if *config == "" {
		fmt.Fprintln(os.Stderr, "--config is required")
		os.Exit(2)
	}
	cfg, e := firefox.ReadConfig(*config)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e := firefox.RunBundle(ctx, *bundle, cfg, os.Stdout, os.Stderr); e != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
