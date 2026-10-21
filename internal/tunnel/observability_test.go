package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/enginestatus"
	"github.com/SawaMEN/FoxTunnel/internal/neqo"
	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

func TestOperationMetricsTCPFailureAndRecovery(t *testing.T) {
	server := &Server{Username: "alice", Password: "secret", AllowPrivate: true}
	c, _ := testClient(t, server)
	target := testDestination(t, func(c net.Conn) { io.Copy(c, c) })
	c.RequireProtocolNegotiation = true
	c.Password = "private-password-marker"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if conn, err := c.DialContext(ctx, "tcp", target); err == nil {
		conn.Close()
		t.Fatal("wrong credential accepted")
	}
	bad := c.TransportStatus().Operations.TCP
	if bad.Started != 1 || bad.Failed != 1 || bad.Active != 0 || bad.Failures.Peer != 1 || bad.LastReason != "peer_rejected" {
		t.Fatal("failed setup metrics", bad)
	}
	c.Password = "secret"
	c.NotifyNetworkChange()
	conn, err := c.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("metric echo")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("metric echo"))
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "metric echo" {
		t.Fatal("metrics changed payload forwarding", err)
	}
	s := c.TransportStatus()
	if s.Operations.TCP.Started != 2 || s.Operations.TCP.Succeeded != 1 || s.Operations.Recovery.AfterFailure != 1 || s.Operations.Recovery.AfterNetworkChange != 1 {
		t.Fatal("successful setup/recovery metrics", s.Operations)
	}
	data, _ := json.Marshal(s)
	for _, secret := range []string{"private-password-marker", target, c.ServerURL.Host} {
		if strings.Contains(string(data), secret) {
			t.Fatal("metrics contain request identity")
		}
	}
}

func TestOperationMetricsUDPExchangeAndStream(t *testing.T) {
	for _, mode := range []string{"h2-connect", "h3-post"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := datagramFixture(t, mode, "go")
			target := startUDPEcho(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := c.ExchangeUDP(ctx, Datagram{Address: target.LocalAddr().String(), Payload: []byte("metric")}); err != nil {
				t.Fatal(err)
			}
			flow, err := c.OpenUDP(ctx)
			if err != nil {
				t.Fatal(err)
			}
			flow.Close()
			s := c.TransportStatus().Operations
			if s.UDPExchange.Started != 1 || s.UDPExchange.Succeeded != 1 || s.UDPExchange.Active != 0 || s.UDPStream.Started != 1 || s.UDPStream.Succeeded != 1 || s.UDPStream.Active != 0 {
				t.Fatal("UDP operation metrics", s)
			}
		})
	}
}

func TestOperationMetricsTypedErrorsAndNoResponse(t *testing.T) {
	c, err := NewClient("https://proxy.invalid", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	for _, test := range []struct {
		err    error
		reason enginestatus.Reason
	}{
		{&tls.CertificateVerificationError{Err: errors.New("private-marker")}, enginestatus.TrustFailed},
		{ErrProtocolNegotiation, enginestatus.ProtocolFailed},
		{context.Canceled, enginestatus.Canceled},
		{context.DeadlineExceeded, enginestatus.Timeout},
		{neqo.ErrCapacity, enginestatus.Capacity},
		{&net.DNSError{Name: "private-marker", Err: "private-marker"}, enginestatus.NetworkFailed},
		{errors.New("private-marker"), enginestatus.OtherFailure},
	} {
		c.transport = probeRoundTripper(func(*http.Request) (*http.Response, error) { return nil, test.err })
		if _, err := c.openTunnel(context.Background(), "private-target.invalid:443"); err == nil {
			t.Fatal("failed transport accepted")
		}
		if got := c.TransportStatus().Operations.TCP.LastReason; got != test.reason.String() {
			t.Fatal("incorrect fixed failure code", got, test.reason)
		}
	}
	for _, status := range []int{204, 426, 429, 503} {
		c.transport = probeRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, ProtoMajor: 2, Body: http.NoBody}, nil
		})
		c.exchangeUDP(context.Background(), []byte("not-sent-by-fake"))
	}
	s := c.TransportStatus()
	if got := s.Operations.UDPExchange; got.Failures.NoReply != 1 || got.Failures.Protocol != 1 || got.Failures.Limited != 2 || got.Succeeded != 0 || got.Active != 0 {
		t.Fatal("UDP refusal/empty-response metrics", got)
	}
	data, _ := json.Marshal(s)
	if strings.Contains(string(data), "private-marker") || strings.Contains(string(data), "private-target") {
		t.Fatal("peer error or target escaped into metrics")
	}
}

func TestOperationMetricsUDPPendingAdmission(t *testing.T) {
	c, err := NewClient("https://proxy.invalid", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	c.EnableUDP = true
	entered, finished := make(chan struct{}, 8), make(chan struct{}, 8)
	c.transport = probeRoundTripper(func(r *http.Request) (*http.Response, error) {
		entered <- struct{}{}
		<-r.Context().Done()
		finished <- struct{}{}
		return nil, r.Context().Err()
	})
	defer c.Close()
	ctrl, bind, code := udpAssociation(t, c)
	if code != 0 {
		t.Fatal("UDP association rejected", code)
	}
	defer ctrl.Close()
	socket, err := net.DialUDP("udp4", nil, bind)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	wire, err := udpproto.Encode(udpproto.Packet{Host: "127.0.0.1", Port: 53, Data: []byte("admission")})
	if err != nil {
		t.Fatal(err)
	}
	for range 8 {
		if _, err := socket.Write(wire); err != nil {
			t.Fatal(err)
		}
	}
	for range 8 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("UDP requests did not occupy admission slots")
		}
	}
	if _, err := socket.Write(wire); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for c.TransportStatus().Operations.Rejections.UDPPending == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := c.TransportStatus().Operations; got.Rejections.UDPPending != 1 || got.UDPExchange.Active != 8 {
		t.Fatal("UDP pending limit was not reported", got)
	}
	ctrl.Close()
	for range 8 {
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("UDP request survived association shutdown")
		}
	}
}
