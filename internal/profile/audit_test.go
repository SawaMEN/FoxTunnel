package profile

import "testing"

func TestAuditLinkRejectsEmptyPort(t *testing.T) {
	_, err := Encode(Config{Version: 1, Servers: []string{"https://node.example:"}, Username: "alice", Password: "secret"})
	if err == nil {
		t.Fatal("link encoder accepted an origin that the SDK refuses")
	}
}

func TestAuditLinkRejectsUnusableUsername(t *testing.T) {
	for _, name := range []string{"a\nb", "a b", "a\u00a0b"} {
		if _, err := Encode(Config{Version: 1, Servers: []string{"https://node.example"}, Username: name, Password: "secret"}); err == nil {
			t.Errorf("unusable username accepted: %q", name)
		}
	}
}
