package udpproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestStreamFramesRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	for _, input := range []Packet{
		{Host: "127.0.0.1", Port: 53, Data: []byte("first")},
		{Host: "::1", Port: 5544, Data: bytes.Repeat([]byte{0x7f}, 800)},
		{Host: "dns.example", Port: 53, Data: []byte("third")},
	} {
		raw, err := Encode(input)
		if err != nil { t.Fatal(err) }
		if err := WriteFrame(&buf, raw); err != nil { t.Fatal(err) }
	}
	for _, host := range []string{"127.0.0.1", "::1", "dns.example"} {
		raw, err := ReadFrame(&buf)
		if err != nil { t.Fatal(err) }
		got, err := Parse(raw)
		if err != nil || got.Host != host { t.Fatalf("got %+v, %v", got, err) }
	}
	if _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) { t.Fatalf("expected EOF, got %v", err) }
}

func TestStreamFrameRejectsInvalidAndTruncated(t *testing.T) {
	p, _ := Encode(Packet{Host:"127.0.0.1",Port:53,Data:[]byte{1}})
	var valid bytes.Buffer
	if err := WriteFrame(&valid,p); err != nil { t.Fatal(err) }
	for _, raw := range [][]byte{
		{0,0},
		{0xff,0xff},
		{0,byte(len(p)),1,2},
		append([]byte{0,byte(len(p))},bytes.Repeat([]byte{0},len(p))...),
	} {
		if _,err := ReadFrame(bytes.NewReader(raw)); err==nil { t.Fatalf("accepted %v",raw[:2]) }
	}
	for i:=1;i<valid.Len();i++ {
		if _,err := ReadFrame(bytes.NewReader(valid.Bytes()[:i])); err==nil { t.Fatalf("accepted truncated frame at %d",i) }
	}
	if err:=WriteFrame(io.Discard, []byte{0}); !errors.Is(err,ErrFrame) { t.Fatalf("accepted malformed frame: %v",err) }
	var oversized [2]byte
	binary.BigEndian.PutUint16(oversized[:],MaxDatagram+1)
	if _,err:=ReadFrame(bytes.NewReader(oversized[:])); !errors.Is(err,ErrFrame) { t.Fatalf("accepted oversized header: %v",err) }
}
