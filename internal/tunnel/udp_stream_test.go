package tunnel

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

func sendStreamTestPacket(t *testing.T, c *net.UDPConn, port int, text string) {
	t.Helper()
	wire, err := udpproto.Encode(udpproto.Packet{Host: "127.0.0.1", Port: uint16(port), Data: []byte(text)})
	if err != nil { t.Fatal(err) }
	if _, err := c.Write(wire); err != nil { t.Fatal(err) }
}

func TestUDPStreamMultiplexDestinations(t *testing.T) {
	a, b := startUDPEcho(t), startUDPEcho(t)
	c, _ := udpFixture(t, &Server{Username: "alice", Password: "secret", EnableUDP: true, AllowPrivate: true})
	c.EnableUDP, c.UDPStreaming = true, true
	control, bind, status := udpAssociation(t, c)
	defer control.Close()
	if status != 0 { t.Fatalf("SOCKS UDP denied %d", status) }
	udp, err := net.DialUDP("udp4", nil, bind)
	if err != nil { t.Fatal(err) }
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(4 * time.Second))
	ap, bp := a.LocalAddr().(*net.UDPAddr).Port, b.LocalAddr().(*net.UDPAddr).Port
	for _, msg := range []struct{ port int; data string }{
		{ap, "a-1"}, {bp, "b-1"}, {ap, "a-2"}, {bp, "b-2"},
	} {
		sendStreamTestPacket(t, udp, msg.port, msg.data)
	}
	got := map[string]int{}
	for i := 0; i < 4; i++ {
		buf := make([]byte, udpproto.MaxDatagram+1)
		n, err := udp.Read(buf)
		if err != nil { t.Fatal(err) }
		p, err := udpproto.Parse(buf[:n])
		if err != nil { t.Fatal(err) }
		if p.Port != uint16(ap) && p.Port != uint16(bp) { t.Fatalf("unsolicited port %d",p.Port) }
		got[string(p.Data)]++
	}
	for _, msg := range []string{"a-1","b-1","a-2","b-2"} {
		if got[msg] != 1 { t.Fatalf("%s: expected once, got %v",msg,got) }
	}
}

func TestUDPStreamMultipleRepliesPerDatagram(t *testing.T) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127,0,0,1)})
	if err != nil { t.Fatal(err) }
	defer target.Close()
	go func() {
		var buf [128]byte
		for {
			n, peer, err := target.ReadFromUDP(buf[:])
			if err != nil { return }
			if n == 0 { continue }
			_, _ = target.WriteToUDP([]byte("reply-1"),peer)
			_, _ = target.WriteToUDP([]byte("reply-2"),peer)
		}
	}()
	c, _ := udpFixture(t, &Server{Username: "alice", Password: "secret", EnableUDP: true, AllowPrivate: true})
	c.EnableUDP, c.UDPStreaming = true, true
	control, bind, status := udpAssociation(t,c)
	defer control.Close()
	if status!=0 { t.Fatalf("SOCKS denied %d",status) }
	udp, err := net.DialUDP("udp4", nil, bind)
	if err != nil { t.Fatal(err) }
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(4 * time.Second))
	sendStreamTestPacket(t,udp,target.LocalAddr().(*net.UDPAddr).Port,"query")
	var responses []string
	for len(responses)<2 {
		var buf [udpproto.MaxDatagram+1]byte
		n, err:=udp.Read(buf[:])
		if err!=nil {t.Fatal(err)}
		packet,err:=udpproto.Parse(buf[:n])
		if err!=nil {t.Fatal(err)}
		responses=append(responses,string(packet.Data))
	}
	if !(responses[0]=="reply-1" && responses[1]=="reply-2") {
		t.Fatalf("lost async replies: %v",responses)
	}
}

func TestUDPStreamAuthorizationAndOptIn(t *testing.T) {
	s := &Server{Username:"alice",Password:"secret",EnableUDP:true}
	for _, tt := range []struct{label string; authenticated bool; enabled bool}{
		{"missing credentials",false,true},{"disabled",true,false},
	} {
		s.EnableUDP=tt.enabled
		req:=httptest.NewRequest(http.MethodPost,"https://example.org"+udpStreamPath,bytes.NewBuffer(nil))
		req.ProtoMajor=2
		if tt.authenticated {req.Header.Set("Proxy-Authorization",basicAuth("alice","secret"))}
		rr:=httptest.NewRecorder()
		s.ServeHTTP(rr,req)
		if rr.Code!=http.StatusNotFound { t.Fatalf("%s: unexpected status %d",tt.label,rr.Code) }
	}
}
