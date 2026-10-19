//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/i18n"
	"github.com/SawaMEN/FoxTunnel/internal/linuxvpn"
	"github.com/SawaMEN/FoxTunnel/internal/profile"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
)

func newVPNHub(ctx context.Context, path string, allowPrivate bool) (http.Handler, error) {
	var config linuxvpn.ServerConfig
	if linuxvpn.ReadConfig(path, &config) != nil || config.Validate() != nil {
		return nil, linuxvpn.ErrConfig
	}
	if linuxvpn.CheckServerNetwork(ctx) != nil {
		return nil, linuxvpn.ErrNetwork
	}
	h := &linuxvpn.Hub{Peers: map[string]linuxvpn.Peer{}, AllowPrivate: allowPrivate}
	for _, p := range config.Peers {
		h.Peers[p.ID] = p
	}
	h.Open = func(ctx context.Context, p linuxvpn.Peer) (linuxvpn.Device, error) {
		hash := sha256.Sum256([]byte(p.ID))
		name := fmt.Sprintf("ftvs%x", hash[:5])
		device, err := linuxvpn.OpenTUN(name)
		if err != nil {
			return nil, err
		}
		if err = linuxvpn.ConfigureDevice(ctx, name, p, false); err != nil {
			device.Close()
			return nil, err
		}
		return device, nil
	}
	return h, nil
}

func vpnCommand(command string, args []string) error {
	fs := i18n.NewFlagSet("foxtunnel " + command)
	configPath := fs.String("config", "", i18n.Text("private VPN configuration JSON"))
	linkPath := fs.String("link-file", "", i18n.Text("private vetroff link file with a literal IP endpoint"))
	ca := fs.String("ca-cert", "", i18n.Text("additional trusted PEM certificate"))
	remove := fs.Bool("remove", false, i18n.Text("explicitly remove VPN server firewall policy"))
	i18n.Parse(fs, args)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if command == "vpn-network" {
		if *linkPath != "" || *ca != "" {
			return linuxvpn.ErrConfig
		}
		var config linuxvpn.ServerConfig
		if linuxvpn.ReadConfig(*configPath, &config) != nil {
			return linuxvpn.ErrConfig
		}
		rules, err := linuxvpn.ServerRules(config)
		if err != nil {
			return err
		}
		if *remove {
			return linuxvpn.RemoveTable(ctx, linuxvpn.ServerTable)
		}
		return linuxvpn.InstallTable(ctx, linuxvpn.ServerTable, rules)
	}
	if *remove {
		return linuxvpn.ErrConfig
	}
	var config linuxvpn.ClientConfig
	if linuxvpn.ReadConfig(*configPath, &config) != nil {
		return linuxvpn.ErrConfig
	}
	info, err := os.Lstat(*linkPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return linuxvpn.ErrConfig
	}
	f, err := os.Open(*linkPath)
	if err != nil {
		return linuxvpn.ErrConfig
	}
	actual, e := f.Stat()
	if e != nil || !os.SameFile(info, actual) {
		f.Close()
		return linuxvpn.ErrConfig
	}
	link, err := profile.Read(f)
	f.Close()
	if err != nil || len(link.Servers) != 1 || link.Bond || link.Discover || link.Padding {
		return linuxvpn.ErrConfig
	}
	origin, err := url.Parse(link.Servers[0])
	if err != nil {
		return linuxvpn.ErrConfig
	}
	endpoint, err := netip.ParseAddr(origin.Hostname())
	if err != nil || config.Validate(endpoint) != nil || link.SNI == "" {
		return linuxvpn.ErrConfig
	}
	port := 443
	if origin.Port() != "" {
		port, err = strconv.Atoi(origin.Port())
		if err != nil {
			return linuxvpn.ErrConfig
		}
	}
	rules, err := linuxvpn.ClientRules(config, endpoint, port, os.Getuid())
	if err != nil {
		return err
	}
	if command == "vpn-down" {
		if linuxvpn.Run(ctx, "nft", []string{"list", "table", "inet", linuxvpn.ClientTable}, "") != nil {
			return linuxvpn.ErrNetwork
		}
		// Removing the blocking table is an explicit disconnect, never an automatic
		// reaction to a process crash, TLS failure or unavailable UDP.
		linuxvpn.Run(ctx, "resolvectl", []string{"revert", config.Interface}, "")
		linuxvpn.Run(ctx, "ip", []string{"link", "delete", config.Interface}, "")
		linuxvpn.Run(ctx, "ip", linuxvpn.EndpointRoute(config, endpoint, "del"), "")
		return linuxvpn.RemoveTable(ctx, linuxvpn.ClientTable)
	}
	client, err := tunnel.NewClient(link.Servers[0], link.Username, link.Password, *ca)
	if err != nil {
		return linuxvpn.ErrConfig
	}
	defer client.Close()
	if client.SetTLSBackend(link.TLSBackend) != nil || client.SetServerIdentity(link.SNI, link.PinSHA256) != nil || client.SetTransport(link.Transport) != nil || client.SetXHTTPSettings(link.XHTTPPath, link.XHTTPHost) != nil {
		return linuxvpn.ErrConfig
	}
	client.ConnectTimeout = 5 * time.Second
	// Refuse collisions before installing the fail-closed policy.
	if _, err := net.InterfaceByName(config.Interface); err == nil {
		return linuxvpn.ErrNetwork
	}
	if !linuxvpn.EndpointRouteFree(ctx, endpoint) {
		return linuxvpn.ErrNetwork
	}
	if linuxvpn.InstallTable(ctx, linuxvpn.ClientTable, rules) != nil {
		return linuxvpn.ErrNetwork
	}
	device, err := linuxvpn.OpenTUN(config.Interface)
	if err != nil {
		return err
	}
	defer device.Close()
	peer := linuxvpn.Peer{IPv4: config.IPv4, IPv6: config.IPv6}
	if linuxvpn.ConfigureDevice(ctx, config.Interface, peer, true) != nil || linuxvpn.ConfigureClientRoutes(ctx, config, endpoint) != nil {
		return linuxvpn.ErrNetwork
	}
	log.Print(i18n.Text("VPN policy installed; direct egress blocked"))
	delay := time.Second
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err := client.DialIP(attempt)
		cancel()
		if err == nil {
			log.Print(i18n.Text("VPN IP session connected"))
			delay = time.Second
			linuxvpn.Relay(ctx, device, conn, peer)
			conn.Close()
		}
		if ctx.Err() != nil {
			break
		}
		log.Print(i18n.Text("VPN disconnected; traffic remains blocked"))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
		delay = min(delay*2, 10*time.Second)
	}
	return nil
}
