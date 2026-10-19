package tunnel

import "testing"

func TestTLSClientProfileRejectsGoAndUnknownNamesWithoutStateChange(t *testing.T) {
	c, err := NewClient("https://example.org", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.SetTLSBackend("go"); err != nil {
		t.Fatal(err)
	}
	old := c.transport
	for _, name := range []string{"unknown", "firefox-158"} {
		if err = c.SetTLSClientProfile(name); err == nil || c.tlsClientProfile != "" || c.transport != old {
			t.Fatal("failed transition changed state", name, err)
		}
	}
}
