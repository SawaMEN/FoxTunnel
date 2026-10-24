package firefox

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Managed owns one verified Necko helper. Canceling a DialContext only cancels
// that setup; Close terminates and joins the helper and removes its profile.
type Managed struct {
	mu          sync.Mutex
	cancel      context.CancelFunc
	lifetime    context.Context
	ready, done chan struct{}
	listen      string
	profileTag  string
	closed      bool
	timeout     time.Duration
	token       string
}

func NewManaged(bundle string, config Config) (*Managed, error) {
	runtimePath, err := VerifyBundle(bundle)
	if err != nil {
		return nil, err
	}
	return newManagedRuntime(runtimePath, config)
}

// newManagedRuntime is internal. Production callers must verify the bundle;
// native research tests may explicitly supply FOXTUNNEL_XPCSHELL as Run does.
func newManagedRuntime(runtimePath string, config Config) (*Managed, error) {
	var err error
	var token [16]byte
	if _, err = rand.Read(token[:]); err != nil {
		return nil, errors.New("cannot create Necko IPC credentials")
	}
	config.SOCKSToken = hex.EncodeToString(token[:])
	config.Listen = "127.0.0.1:0"
	config, err = config.normalize()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Managed{lifetime: ctx, cancel: cancel, ready: make(chan struct{}), done: make(chan struct{}), timeout: time.Duration(config.ConnectTimeoutMS) * time.Millisecond, token: config.SOCKSToken}
	r, w := io.Pipe()
	go func() {
		defer r.Close()
		d := json.NewDecoder(r)
		for {
			var event struct {
				Type       string `json:"type"`
				Listen     string `json:"listen"`
				ProfileTag string `json:"process_tag"`
			}
			if d.Decode(&event) != nil {
				return
			}
			if event.Type != "ready" {
				continue
			}
			host, port, e := net.SplitHostPort(event.Listen)
			n, pe := strconv.Atoi(port)
			if e != nil || pe != nil || host != "127.0.0.1" || n < 1 || n > 65535 {
				cancel()
				return
			}
			m.mu.Lock()
			if m.listen == "" {
				m.listen = event.Listen
				m.profileTag = event.ProfileTag
				close(m.ready)
			}
			m.mu.Unlock()
		}
	}()
	go func() {
		defer close(m.done)
		// Raw Gecko diagnostics can contain headers or destinations. They are
		// never mixed with the CLI's process-event protocol or SDK status.
		err := Run(ctx, runtimePath, config, w, io.Discard)
		w.CloseWithError(err)
	}()
	return m, nil
}

func (m *Managed) Ready(ctx context.Context) error {
	t := time.NewTimer(m.timeout)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.done:
		return errors.New("Necko helper stopped")
	case <-t.C:
		return context.DeadlineExceeded
	case <-m.ready:
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	select {
	case <-m.done:
		return errors.New("Necko helper stopped")
	default:
		return nil
	}
}

func (m *Managed) Close() error {
	m.mu.Lock()
	m.closed = true
	m.cancel()
	m.mu.Unlock()
	<-m.done
	return nil
}

func (m *Managed) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, net.UnknownNetworkError(network)
	}
	host, port, err := net.SplitHostPort(address)
	n, pe := strconv.Atoi(port)
	if err != nil || pe != nil || n < 1 || n > 65535 || host == "" {
		return nil, errors.New("invalid Necko destination")
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			request = append(append(request, 1), v4...)
		} else {
			request = append(append(request, 4), ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("invalid Necko destination")
		}
		for _, b := range []byte(host) {
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '.' || b == '-' || b == '_') {
				return nil, errors.New("invalid Necko destination")
			}
		}
		request = append(append(request, 3, byte(len(host))), []byte(host)...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(n))
	setup, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	if err = m.Ready(setup); err != nil {
		return nil, err
	}
	m.mu.Lock()
	listen := m.listen
	m.mu.Unlock()
	c, err := (&net.Dialer{}).DialContext(setup, "tcp", listen)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			c.Close()
		}
	}()
	deadline, _ := setup.Deadline()
	c.SetDeadline(deadline)
	stop := context.AfterFunc(setup, func() { c.Close() })
	defer stop()
	write := func(b []byte) error {
		for len(b) > 0 {
			n, e := c.Write(b)
			if e != nil {
				return e
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			b = b[n:]
		}
		return nil
	}
	var greeting [2]byte
	if err = write([]byte{5, 1, 2}); err == nil {
		_, err = io.ReadFull(c, greeting[:])
	}
	if err != nil {
		return nil, err
	}
	if greeting != [2]byte{5, 2} {
		return nil, errors.New("Necko local handshake failed")
	}
	auth := append([]byte{1, 9}, []byte("foxtunnel")...)
	auth = append(auth, byte(len(m.token)))
	auth = append(auth, []byte(m.token)...)
	if err = write(auth); err == nil {
		_, err = io.ReadFull(c, greeting[:])
	}
	if err != nil {
		return nil, err
	}
	if greeting != [2]byte{1, 0} {
		return nil, errors.New("Necko IPC authentication failed")
	}
	if err = write(request); err != nil {
		return nil, err
	}
	var reply [4]byte
	if _, err = io.ReadFull(c, reply[:]); err != nil {
		return nil, err
	}
	if reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
		return nil, errors.New("Necko CONNECT rejected")
	}
	size := 0
	switch reply[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var b [1]byte
		if _, err = io.ReadFull(c, b[:]); err != nil {
			return nil, err
		}
		size = int(b[0])
	default:
		return nil, errors.New("invalid Necko local reply")
	}
	if _, err = io.ReadFull(c, make([]byte, size+2)); err != nil {
		return nil, err
	}
	if !stop() || setup.Err() != nil {
		return nil, setup.Err()
	}
	c.SetDeadline(time.Time{})
	success = true
	// Return the TCP socket itself: half-close and deadlines survive the
	// in-process SDK adapter. No application traffic uses Go HTTP/TLS.
	return c, nil
}
