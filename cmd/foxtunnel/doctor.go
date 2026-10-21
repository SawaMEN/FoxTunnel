package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/cluster"
	"github.com/SawaMEN/FoxTunnel/internal/contract"
	"github.com/SawaMEN/FoxTunnel/internal/profile"
	"github.com/SawaMEN/FoxTunnel/internal/transportengine"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
)

const doctorPayloadBytes = 32

var errDoctor = errors.New("connection diagnosis failed")

type doctorOptions struct {
	linkFile, ca, engine, target, network string
	serverIndex                           int
	timeout                               time.Duration
}

type doctorCheck struct {
	Stage      string `json:"stage"`
	OK         bool   `json:"ok"`
	Reason     string `json:"reason"`
	DurationMS int64  `json:"duration_ms"`
	HTTPMajor  int    `json:"http_major,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

type doctorReport struct {
	ProtocolPolicy contract.ProtocolPolicy `json:"protocol_policy,omitempty"`
	Schema         int                     `json:"schema"`
	OK             bool                    `json:"ok"`
	Network        string                  `json:"network"`
	ServerIndex    int                     `json:"server_index"`
	Transport      string                  `json:"transport,omitempty"`
	Engine         string                  `json:"engine,omitempty"`
	Checks         []doctorCheck           `json:"checks"`
	DurationMS     int64                   `json:"duration_ms"`
}

func (r *doctorReport) add(stage string, started time.Time, reason string, err error) {
	r.Checks = append(r.Checks, doctorCheck{Stage: stage, OK: err == nil, Reason: reason, DurationMS: time.Since(started).Milliseconds()})
	if err != nil {
		r.OK = false
	}
}

func doctorCommand(parent context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("foxtunnel doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // Never echo invalid values, paths or flag names.
	o := doctorOptions{}
	fs.StringVar(&o.linkFile, "link-file", "", "private client profile file")
	fs.StringVar(&o.ca, "ca-cert", "", "additional trusted certificate PEM")
	fs.StringVar(&o.engine, "engine", "legacy", "client engine: legacy or mozilla")
	fs.StringVar(&o.target, "target", "", "operator-controlled echo service host:port; receives 32 random bytes")
	fs.StringVar(&o.network, "network", "tcp", "echo service protocol: tcp or udp")
	fs.IntVar(&o.serverIndex, "server-index", 0, "zero-based profile server index; probes this node without balancing or bonding")
	fs.DurationVar(&o.timeout, "timeout", 15*time.Second, "total probe budget, 100ms through 2m")
	asJSON := fs.Bool("json", false, "print a schema-1 JSON report without addresses or secrets")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(out)
			fmt.Fprintln(out, "usage: foxtunnel doctor --link-file FILE --target HOST:PORT [--network tcp|udp] [--json]")
			fs.PrintDefaults()
			return nil
		}
		return errors.New("invalid doctor arguments; use --help")
	}
	if fs.NArg() != 0 || o.linkFile == "" || o.linkFile == "-" || o.serverIndex < 0 || o.serverIndex > 7 || o.timeout < 100*time.Millisecond || o.timeout > 2*time.Minute || (o.network != "tcp" && o.network != "udp") || !doctorTargetValid(o.target) {
		return errors.New("doctor requires a profile file, valid echo target, tcp/udp mode, server index 0..7 and timeout 100ms..2m")
	}
	ctx, cancel := context.WithTimeout(parent, o.timeout)
	defer cancel()
	r := runDoctor(ctx, o, net.DefaultResolver.LookupIPAddr)
	if *asJSON {
		if err := json.NewEncoder(out).Encode(r); err != nil {
			return errors.New("cannot write diagnosis report")
		}
	} else {
		for _, check := range r.Checks {
			status := "PASS"
			if !check.OK {
				status = "FAIL"
			}
			if _, err := fmt.Fprintf(out, "%s %s: %s (%d ms)\n", status, check.Stage, check.Reason, check.DurationMS); err != nil {
				return errors.New("cannot write diagnosis report")
			}
		}
	}
	if !r.OK {
		return errDoctor
	}
	return nil
}

func doctorTargetValid(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || strings.ContainsAny(host, "/\\\r\n\t @?#%") {
		return false
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

// Only fixed local codes escape this classifier. Never match error strings:
// remote replies and underlying filesystem/DNS errors can contain secrets.
func doctorReason(err error, fallback string) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, tunnel.ErrProtocolNegotiation) {
		return "protocol_negotiation_failed"
	}
	var verification *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var roots x509.SystemRootsError
	if errors.As(err, &verification) || errors.As(err, &authority) || errors.As(err, &hostname) || errors.As(err, &invalid) || errors.As(err, &roots) {
		return "tls_trust_failed"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	var response *tunnel.ConnectResponseError
	if errors.As(err, &response) {
		switch response.HTTPStatus {
		case 426:
			return "protocol_negotiation_failed"
		case 401, 403, 407:
			return "authentication_or_policy_rejected"
		case 429, 503:
			return "server_limited_or_unavailable"
		case 502, 504:
			return "destination_or_policy_unavailable"
		default:
			return "tunnel_rejected"
		}
	}
	return fallback
}

func runDoctor(ctx context.Context, o doctorOptions, lookup func(context.Context, string) ([]net.IPAddr, error)) (r doctorReport) {
	started := time.Now()
	defer func() { r.DurationMS = time.Since(started).Milliseconds() }()
	r = doctorReport{Schema: 1, OK: true, Network: o.network, ServerIndex: o.serverIndex, Checks: []doctorCheck{}}
	step := time.Now()
	c, err := profile.ReadSecretFile(o.linkFile)
	if err == nil && o.serverIndex >= len(c.Servers) {
		err = errDoctor
	}
	if err == nil && o.ca != "" {
		err = regularConfigFile(o.ca)
	}
	r.add("profile", step, doctorReason(err, "invalid_profile_or_local_files"), err)
	if err != nil {
		return r
	}
	r.ProtocolPolicy = c.ProtocolPolicy.Effective()
	step = time.Now()
	// Intentionally disable H3 fallback: a successful H2 fallback cannot prove
	// this node's UDP/QUIC path works. Other nodes and discovery are not probed.
	plan, err := transportengine.Resolve(transportengine.Config{Engine: o.engine, Transport: c.Transport, TLSBackend: c.TLSBackend, H3Fallback: "none"})
	var client *tunnel.Client
	if err == nil {
		client, err = tunnel.NewClient(c.Servers[o.serverIndex], c.Username, c.Password, o.ca)
	}
	if client != nil {
		defer client.Close()
	}
	if err == nil {
		// Profile SNI/pin belong to its primary origin only, matching the
		// normal client's fallback identity policy.
		sni, pin := c.SNI, c.PinSHA256
		if o.serverIndex != 0 {
			sni, pin = "", ""
		}
		err = plan.Apply(client, sni, pin)
	}
	if err == nil {
		err = client.SetXHTTPSettings(c.XHTTPPath, c.XHTTPHost)
	}
	r.add("configuration", step, doctorReason(err, "engine_or_trust_configuration_failed"), err)
	if err != nil {
		return r
	}
	r.Transport, r.Engine = plan.Transport, plan.Engine
	client.RequireProtocolNegotiation = c.ProtocolPolicy == contract.ProtocolStrict
	client.Padding = c.Padding
	client.ConnectTimeout, _ = time.ParseDuration(c.ConnectTimeout)
	client.EnableUDP = o.network == "udp"
	step = time.Now()
	origin, _ := cluster.Origin(c.Servers[o.serverIndex]) // Validated by profile.
	if err = ctx.Err(); err == nil && net.ParseIP(origin.Hostname()) == nil {
		var ips []net.IPAddr
		ips, err = lookup(ctx, origin.Hostname())
		if err == nil && len(ips) == 0 {
			err = errDoctor
		}
	}
	r.add("dns", step, doctorReason(err, "proxy_dns_failed"), err)
	if err != nil {
		return r
	}
	step = time.Now()
	probe, err := client.ProbeTransport(ctx)
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	r.add("transport", step, doctorReason(err, "tls_or_carrier_failed"), err)
	last := &r.Checks[len(r.Checks)-1]
	last.HTTPMajor, last.HTTPStatus = probe.HTTPMajor, probe.HTTPStatus
	if err != nil {
		return r
	}
	payload := make([]byte, doctorPayloadBytes)
	if _, err = rand.Read(payload); err != nil {
		r.add("payload", time.Now(), "random_source_failed", err)
		return r
	}
	if o.network == "udp" {
		step = time.Now()
		reply, exchangeErr := client.ExchangeUDP(ctx, tunnel.Datagram{Address: o.target, Payload: payload})
		err = exchangeErr
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		reason := doctorReason(err, "udp_exchange_failed")
		if err == nil && !bytes.Equal(payload, reply.Payload) {
			err, reason = errDoctor, "echo_mismatch"
		}
		r.add("udp_echo", step, reason, err)
		return r
	}
	step = time.Now()
	conn, err := client.DialContext(ctx, "tcp", o.target)
	r.add("tunnel", step, doctorReason(err, "tunnel_setup_failed"), err)
	if err != nil {
		return r
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	step = time.Now()
	if deadline, ok := ctx.Deadline(); ok {
		err = conn.SetDeadline(deadline)
	}
	if err == nil {
		var n int
		n, err = conn.Write(payload)
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}
	}
	response := make([]byte, doctorPayloadBytes)
	if err == nil {
		_, err = io.ReadFull(conn, response)
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	reason := doctorReason(err, "tcp_exchange_failed")
	if err == nil && !bytes.Equal(payload, response) {
		err, reason = errDoctor, "echo_mismatch"
	}
	r.add("tcp_echo", step, reason, err)
	return r
}
