package firefox

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"os"
	"testing"
)

func TestFingerprintRFC9001Initial(t *testing.T) {
	data, e := os.ReadFile("fingerprint/rfc9001-initial.json")
	if e != nil {
		t.Fatal(e)
	}
	var vector struct {
		Packet string `json:"packet"`
		Crypto string `json:"crypto_frame"`
	}
	if e := json.Unmarshal(data, &vector); e != nil {
		t.Fatal(e)
	}
	packet, _ := hex.DecodeString(vector.Packet)
	want, _ := hex.DecodeString(vector.Crypto)
	id, plain, used, e := fpDecryptInitial(packet)
	if e != nil || used != len(packet) || id != "8394c8f03e515708" || !bytes.HasPrefix(plain, want) {
		t.Fatalf("RFC 9001 vector: used=%d id=%s err=%v", used, id, e)
	}
	initial := &fpInitial{}
	initial.feed(plain)
	if initial.err != "" || initial.hello == nil || len(initial.hello.CipherSuites) != 2 {
		t.Fatalf("RFC ClientHello reassembly: %+v", initial.hello)
	}
	packet[len(packet)-1] ^= 1
	if _, _, _, e := fpDecryptInitial(packet); e == nil {
		t.Fatal("accepted unauthenticated Initial")
	}
	for j := 0; j < len(packet); j++ {
		if _, _, _, e := fpDecryptInitial(packet[:j]); e == nil {
			t.Fatalf("accepted truncated Initial %d", j)
		}
	}
}

func TestFingerprintHPACKFragmentationAndReuse(t *testing.T) {
	var raw, block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	fields := []hpack.HeaderField{{Name: ":method", Value: "CONNECT"}, {Name: ":authority", Value: "fixture.invalid:443"}, {Name: "proxy-authorization", Value: "never-publish-this"}}
	for _, f := range fields {
		if e := enc.WriteField(f); e != nil {
			t.Fatal(e)
		}
	}
	fr := http2.NewFramer(&raw, nil)
	raw.WriteString(http2.ClientPreface)
	fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65535})
	b := append([]byte(nil), block.Bytes()...)
	fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: b[:3]})
	fr.WriteContinuation(1, true, b[3:])
	fr.WriteData(1, true, nil)
	block.Reset()
	for _, f := range fields {
		enc.WriteField(f)
	}
	fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: block.Bytes(), EndHeaders: true})
	capture := &fpCapture{}
	p := &fpConnection{}
	tap := &fpTap{owner: capture, p: p, decoder: hpack.NewDecoder(65536, nil)}
	for _, v := range raw.Bytes() {
		tap.feed([]byte{v})
	}
	if p.Error != "" || p.Truncated || len(p.Blocks) != 2 || len(p.Fins) != 1 || p.Blocks[1].Length >= p.Blocks[0].Length {
		t.Fatalf("fragmented HPACK capture: %+v", p)
	}
	serialized, _ := json.Marshal(p)
	if bytes.Contains(serialized, []byte("never-publish")) || bytes.Contains(serialized, []byte("fixture.invalid")) {
		t.Fatal("leaked header values")
	}
}
