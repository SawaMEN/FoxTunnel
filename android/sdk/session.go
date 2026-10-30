// Package androidsdk provides a small Java/Kotlin-compatible VetroffProxy API.
// It is a standalone SOCKS adapter, not the sing-box in-process outbound.
package androidsdk

import (
	"encoding/json"
	"errors"
	"net"
	"sync"

	vetroff "github.com/SawaMEN/VetroffProxy"
)

// Session owns one VetroffProxy client and an optional localhost SOCKS server.
type Session struct {
	mu       sync.Mutex
	client   *vetroff.Client
	listener net.Listener
	closed   bool
	lastErr  string
}

// NewSession validates a canonical vetroff:// link, including its credentials.
// Keep the link confidential; never write it to logs.
func NewSession(link string) (*Session, error) {
	client, err := vetroff.NewClientFromLink(link)
	if err != nil {
		return nil, err
	}
	return &Session{client: client}, nil
}

// StartSOCKS starts a private, unauthenticated SOCKS5 listener on a random
// 127.0.0.1 TCP port. The Android host owns VPN routing and outer socket bypass.
func (s *Session) StartSOCKS() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.client == nil {
		return 0, net.ErrClosed
	}
	if s.listener != nil {
		return 0, errors.New("SOCKS listener already running")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	s.listener = ln
	go func() {
		err := s.client.ServeSOCKS(ln)
		s.mu.Lock()
		if err != nil && !s.closed {
			// Do not expose transport errors, link secrets or remote addresses.
			s.lastErr = "SOCKS listener stopped unexpectedly"
		}
		if s.listener == ln {
			s.listener = nil
		}
		s.mu.Unlock()
	}()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// LastError is a fixed diagnostic label without remote addresses or secrets.
func (s *Session) LastError() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

// StatusJSON returns secret-free aggregate connection counts and transport state.
func (s *Session) StatusJSON() string {
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()
	if client == nil {
		return "{}"
	}
	data, err := json.Marshal(client.Snapshot())
	if err != nil {
		return "{}"
	}
	return string(data)
}

// NotifyNetworkChange invalidates cached transport paths for new sessions.
func (s *Session) NotifyNetworkChange() error {
	s.mu.Lock()
	client, closed := s.client, s.closed
	s.mu.Unlock()
	if client == nil || closed {
		return net.ErrClosed
	}
	return client.NotifyNetworkChange()
}

// Stop is idempotent and closes all streams and its local SOCKS listener.
func (s *Session) Stop() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln, client := s.listener, s.client
	s.listener = nil
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	if client != nil {
		return client.Close()
	}
	return nil
}
