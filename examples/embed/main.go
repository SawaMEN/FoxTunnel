// Example: embed the public client in an ordinary HTTP client. No panel or CLI.
package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"time"

	ft "github.com/SawaMEN/VetroffProxy"
)

func main() {
	client, err := ft.NewClient(ft.ClientConfig{ServerURL: os.Getenv("VETROFF_SERVER"), Credentials: ft.Credentials{Username: os.Getenv("VETROFF_USER"), Password: os.Getenv("VETROFF_PASSWORD")}, CACertFile: os.Getenv("VETROFF_CA"), Transport: "xhttp-packet-up"})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	transport := &http.Transport{DialContext: client.DialContext}
	defer transport.CloseIdleConnections()
	browser := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	resp, err := browser.Get("https://example.com/")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err = io.Copy(os.Stdout, resp.Body); err != nil {
		log.Fatal(err)
	}
}
