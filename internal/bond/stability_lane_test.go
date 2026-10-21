package bond

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

// A server may retire an idle persistent lane while the bound hub session
// remains active on other lanes. Reusing that lane must not reset TCP.
func TestStableRetiredLanePreservesBoundSession(t *testing.T) {
	dial, dials := echoDial(t)
	c, _, _ := laneFixture(t, dial)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	s, err := c.Open(ctx, "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	first, second := []byte("before idle retirement"), []byte("after idle retirement")
	if _, err := c.requestVia(ctx, s.transport, s.token[:], s.hub, opWrite, 0, 0, first, nil); err != nil {
		t.Fatal(err)
	}
	s.lanes.mu.Lock()
	if len(s.lanes.lanes) != 1 {
		s.lanes.mu.Unlock()
		t.Fatal("expected one upload lane")
	}
	lane := s.lanes.lanes[0]
	s.lanes.mu.Unlock()
	lane.stop() // Same local writer/body state as an idle server-side retirement.
	c.mu.Lock()
	for i, endpoint := range c.Endpoints {
		if endpoint.String()+Path == lane.endpoint {
			c.paths[i].retryAt = time.Time{}
		} else {
			c.paths[i].retryAt = time.Now().Add(time.Minute)
		}
	}
	c.mu.Unlock()
	if _, err := c.requestVia(ctx, s.transport, s.token[:], s.hub, opWrite, 1, 0, second, nil); err != nil {
		t.Fatal("retired lane reset the live session:", err)
	}
	got := make([]byte, len(first)+len(second))
	if _, err := io.ReadFull(s, got); err != nil || !bytes.Equal(got, append(first, second...)) {
		t.Fatalf("recovery lost/replayed data: %q %v", got, err)
	}
	if dials.Load() != 1 {
		t.Fatalf("recovery reopened destination: %d", dials.Load())
	}
}
