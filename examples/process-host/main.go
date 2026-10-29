// A host uses SOCKS with its own HTTP client; it owns VPN routes and DNS.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/SawaMEN/VetroffProxy/processhost"
)

func main() {
	binary := flag.String("binary", "", "absolute verified Vetroff executable path")
	link := flag.String("link-file", "", "absolute private connection file path")
	ca := flag.String("ca-cert", "", "optional extra trusted CA PEM")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	child, err := processhost.StartClient(ctx, processhost.ClientOptions{Executable: *binary, LinkFile: *link, CACertFile: *ca})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("SOCKS5", child.Address)
	if err := child.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
