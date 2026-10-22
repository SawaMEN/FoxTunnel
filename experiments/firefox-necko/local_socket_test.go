package firefox

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Isolate the local SOCKS socket's FIN contract from native HTTP stream EOF.
// The independent TCP peer must see FIN, then still be able to upload to Gecko.
func TestGeckoLocalHalfClose(t *testing.T) {
	runtime := os.Getenv("FOXTUNNEL_XPCSHELL")
	if runtime == "" {
		t.Skip("set FOXTUNNEL_XPCSHELL to a real Gecko runtime")
	}
	script := filepath.Join(t.TempDir(), "local-half-close.js")
	if err := os.WriteFile(script, []byte(localHalfCloseScript), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	read, write := io.Pipe()
	stderr := new(lockedBuffer)
	cmd := exec.CommandContext(ctx, runtime, "-g", filepath.Dir(runtime), "-a", filepath.Dir(runtime), "-f", script)
	cmd.Env = append(os.Environ(), "MOZ_DISABLE_SOCKET_PROCESS=1", "LD_LIBRARY_PATH="+filepath.Dir(runtime))
	cmd.Stdout, cmd.Stderr = write, stderr
	cmd.WaitDelay = time.Second
	finished := make(chan error, 1)
	go func() {
		err := cmd.Run()
		write.CloseWithError(err)
		finished <- err
	}()
	t.Cleanup(func() { cancel(); read.Close(); <-finished })
	decoder := json.NewDecoder(read)
	var ready struct{ Port int }
	if err := decoder.Decode(&ready); err != nil {
		t.Fatalf("native local socket startup: %v\n%s", err, stderr.text())
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(ready.Port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	var marker [1]byte
	if _, err := io.ReadFull(conn, marker[:]); err != nil || marker[0] != 'x' {
		t.Fatal("native output did not drain before FIN", marker, err)
	}
	if n, err := conn.Read(marker[:]); n != 0 || err != io.EOF {
		t.Fatalf("local TCP output.close did not send FIN: n=%d err=%v\n%s", n, err, stderr.text())
	}
	const payload = "upload-after-response-fin"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal("upload after local FIN", err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var uploaded struct{ Upload string }
	if err := decoder.Decode(&uploaded); err != nil || uploaded.Upload != payload {
		t.Fatalf("native input after local FIN: %q err=%v\n%s", uploaded.Upload, err, stderr.text())
	}
}

const localHalfCloseScript = `
const { classes: Cc, interfaces: Ci, results: Cr } = Components;
const thread = Services.tm.mainThread;
const server = Cc["@mozilla.org/network/server-socket;1"].createInstance(Ci.nsIServerSocket);
server.init(-1, true, 4);
let done = false;
const keep = [];
server.asyncListen({
  onSocketAccepted(socket, transport) {
    if (typeof Ci.nsISocketTransport.ENABLE_TCP_HALF_CLOSE === "number") {
      transport.connectionFlags |= Ci.nsISocketTransport.ENABLE_TCP_HALF_CLOSE;
    }
    const input = transport.openInputStream(0, 0, 0).QueryInterface(Ci.nsIAsyncInputStream);
    const output = transport.openOutputStream(0, 0, 0);
    keep.push(transport, input, output);
    output.write("x", 1);
    output.close();
    let upload = "";
    const eof = () => { print(JSON.stringify({ upload })); done = true; };
    const callback = {
      onInputStreamReady(stream) {
        try {
          const n = stream.available();
          if (!n) { eof(); return; }
          if (upload.length + n > 1024) throw new Error("unexpected input size");
          const binary = Cc["@mozilla.org/binaryinputstream;1"].createInstance(Ci.nsIBinaryInputStream);
          binary.setInputStream(stream);
          upload += binary.readBytes(n);
          stream.asyncWait(callback, 0, 0, thread);
        } catch (e) {
          if (e.result === Cr.NS_BASE_STREAM_CLOSED) eof();
          else if (e.result === Cr.NS_BASE_STREAM_WOULD_BLOCK) stream.asyncWait(callback, 0, 0, thread);
          else throw e;
        }
      }, QueryInterface: ChromeUtils.generateQI(["nsIInputStreamCallback"]),
    };
    input.asyncWait(callback, 0, 0, thread);
  },
  onStopListening() {},
  QueryInterface: ChromeUtils.generateQI(["nsIServerSocketListener"]),
});
print(JSON.stringify({ port: server.port }));
while (!done) thread.processNextEvent(true);
server.close();
`
