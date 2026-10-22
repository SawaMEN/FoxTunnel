//go:build neqo && cgo && linux && amd64

package neqo

import "time"

type session struct {
	token, certificates []byte
	expires             time.Time
}

// Tokens never cross transports or origins. Taking removes a ticket before
// another actor can use it. The origin pool and ticket cache have equal bounds.
func (c *connection) takeSession() session {
	t := c.owner
	t.mu.Lock()
	defer t.mu.Unlock()
	key := c.origin + "\x00" + c.name
	s := t.sessions[key]
	delete(t.sessions, key)
	if t.config.SessionTicketsDisabled || !time.Now().Before(s.expires) {
		return session{}
	}
	return s
}
func (c *connection) saveSession(token []byte, seconds uint64) {
	t := c.owner
	if t.config.SessionTicketsDisabled || len(token) == 0 || len(token) > 64<<10 || len(c.peerDER) == 0 || len(c.peerDER) > maxMetadata || seconds == 0 || seconds > 24*60*60 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sessions == nil {
		t.sessions = make(map[string]session)
	}
	for key, s := range t.sessions {
		if !time.Now().Before(s.expires) {
			delete(t.sessions, key)
		}
	}
	key := c.origin + "\x00" + c.name
	if _, ok := t.sessions[key]; !ok && len(t.sessions) >= maxOrigins {
		var oldest string
		var expiry time.Time
		for key, s := range t.sessions {
			if expiry.IsZero() || s.expires.Before(expiry) {
				oldest, expiry = key, s.expires
			}
		}
		delete(t.sessions, oldest)
	}
	t.sessions[key] = session{token: append([]byte(nil), token...), certificates: append([]byte(nil), c.peerDER...), expires: time.Now().Add(time.Duration(seconds) * time.Second)}
}
