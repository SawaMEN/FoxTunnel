//go:build nss && cgo && linux

package nsstls

import (
	"crypto/x509"
	"sync"
	"time"
)

// A transport owns at most eight origin-bound, single-use tickets. The NSS
// process cache is bypassed; no ticket is shared with another transport.
type session struct {
	token        []byte
	certificates []*x509.Certificate
	expires      time.Time
	sequence     uint64
}
type sessionCache struct {
	mu       sync.Mutex
	entries  map[string]session
	sequence uint64
}

func (s *sessionCache) take(key string) session {
	s.mu.Lock()
	defer s.mu.Unlock()
	cached := s.entries[key]
	delete(s.entries, key)
	if !time.Now().Before(cached.expires) {
		return session{}
	}
	return cached
}
func (s *sessionCache) put(key string, cached session) {
	if len(cached.token) == 0 || len(cached.token) > 64<<10 || len(cached.certificates) == 0 || !time.Now().Before(cached.expires) {
		return
	}
	size := 0
	for _, cert := range cached.certificates {
		size += len(cert.Raw)
	}
	if size > 1<<20 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries == nil {
		s.entries = make(map[string]session)
	}
	for k, entry := range s.entries {
		if !time.Now().Before(entry.expires) {
			delete(s.entries, k)
		}
	}
	if _, ok := s.entries[key]; !ok && len(s.entries) >= 8 {
		var oldest string
		var sequence uint64 = ^uint64(0)
		for k, entry := range s.entries {
			if entry.sequence < sequence {
				oldest, sequence = k, entry.sequence
			}
		}
		delete(s.entries, oldest)
	}
	s.sequence++
	cached.sequence = s.sequence
	s.entries[key] = cached
}
