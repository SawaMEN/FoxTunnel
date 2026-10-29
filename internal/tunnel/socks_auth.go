package tunnel

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"strings"
)

// ValidateSOCKSAuth checks optional local SOCKS5 credentials before Serve.
// RFC 1929 limits each field to one-byte length; no password flags are used.
func (c *Client) ValidateSOCKSAuth() error {
	user, pass := c.SOCKSUsername, c.SOCKSPassword
	if user == "" && pass == "" {
		return nil
	}
	if len(user) == 0 || len(user) > 255 || len(pass) == 0 || len(pass) > 255 ||
		strings.ContainsAny(user, "\x00\r\n") {
		return errors.New("VETROFF_SOCKS_USER and VETROFF_SOCKS_PASSWORD must both be valid 1..255-byte credentials")
	}
	return nil
}

// RFC 1928 method negotiation followed by RFC 1929 username/password when
// explicitly configured. Never allow a downgrade to no-auth in that mode.
func socks5Greeting(conn net.Conn, username, password string) error {
	var hello [2]byte
	if _, err := io.ReadFull(conn, hello[:]); err != nil {
		return err
	}
	if hello[0] != 5 || hello[1] == 0 {
		return errors.New("unsupported SOCKS greeting")
	}
	methods := make([]byte, int(hello[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	selected := byte(0)
	if username != "" {
		selected = 2
	}
	supported := false
	for _, m := range methods {
		if m == selected {
			supported = true
			break
		}
	}
	if !supported {
		_, _ = conn.Write([]byte{5, 0xff})
		return errors.New("required SOCKS authentication method unavailable")
	}
	if _, err := conn.Write([]byte{5, selected}); err != nil {
		return err
	}
	if selected == 0 {
		return nil
	}
	// RFC 1929: VER=1 ULEN UNAME PLEN PASSWD.
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return err
	}
	if head[0] != 1 || head[1] == 0 {
		return errors.New("invalid SOCKS authentication request")
	}
	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}
	var passLen [1]byte
	if _, err := io.ReadFull(conn, passLen[:]); err != nil {
		return err
	}
	if passLen[0] == 0 {
		return errors.New("empty SOCKS password")
	}
	pass := make([]byte, int(passLen[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}
	u1, u2 := sha256.Sum256(user), sha256.Sum256([]byte(username))
	p1, p2 := sha256.Sum256(pass), sha256.Sum256([]byte(password))
	accepted := subtle.ConstantTimeCompare(u1[:], u2[:])&subtle.ConstantTimeCompare(p1[:], p2[:]) == 1
	// Clear credential buffers promptly (they were received without TLS on
	// the local SOCKS connection). Never include secrets in error messages.
	clear(user)
	clear(pass)
	if !accepted {
		_, _ = conn.Write([]byte{1, 1})
		return errors.New("SOCKS authentication failed")
	}
	if _, err := conn.Write([]byte{1, 0}); err != nil {
		return err
	}
	return nil
}
