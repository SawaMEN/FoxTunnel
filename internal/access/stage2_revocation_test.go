package access

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// A non-cooperative dialer can finish after policy rotation. Its returned
// socket must never become available to a revoked user, even briefly.
func TestStage2SlowDialRevokedBeforeHandoff(t *testing.T) {
	for _, scenario := range []string{"rotate", "disable", "remove", "controller-close", "request-cancel"} {
		t.Run(scenario, func(t *testing.T) {
			d := policy()
			d.Users[0].MaxTunnels = 1
			c := newTest(t, d, "")
			ctx, done := begin(t, c, "alice", secretA)
			defer done()

			entered := make(chan struct{})
			release := make(chan struct{})
			raw := new(sink)
			type outcome struct {
				conn net.Conn
				err  error
			}
			finished := make(chan outcome, 1)
			go func() {
				conn, err := Dial(ctx, func(context.Context) (net.Conn, error) {
					close(entered)
					<-release // deliberately ignore ctx.Done()
					return raw, nil
				})
				finished <- outcome{conn, err}
			}()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("dial was not admitted")
			}
			if got := c.Snapshot().Users[0].ActiveTunnels; got != 1 {
				t.Fatalf("unaccounted pending dial: %d", got)
			}

			switch scenario {
			case "rotate":
				d.Users[0].Password = secretA + "-new"
				if err := c.Replace(d); err != nil {
					t.Fatal(err)
				}
			case "disable":
				d.Users[0].Disabled = true
				if err := c.Replace(d); err != nil {
					t.Fatal(err)
				}
			case "remove":
				d.Users = d.Users[1:]
				if err := c.Replace(d); err != nil {
					t.Fatal(err)
				}
			case "controller-close":
				if err := c.Close(); err != nil {
					t.Fatal(err)
				}
			case "request-cancel":
				done()
			}
			close(release)
			select {
			case result := <-finished:
				if result.conn != nil {
					_ = result.conn.Close()
					t.Fatal("published a socket after revocation or cancellation")
				}
				if scenario == "request-cancel" {
					if !errors.Is(result.err, context.Canceled) {
						t.Fatalf("expected request cancellation, got %v", result.err)
					}
				} else if !errors.Is(result.err, ErrDenied) {
					t.Fatalf("expected denial, got %v", result.err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("non-cooperative dial did not finish")
			}
			if !raw.closed.Load() {
				t.Fatal("socket returned by late dialer was not closed")
			}
			c.mu.Lock()
			active := c.accounts["a"].tunnels
			c.mu.Unlock()
			if active != 0 {
				t.Fatalf("late dial leaked %d admission slots", active)
			}
		})
	}
}

func TestStage2RevocationClosesEstablishedBlockedSocket(t *testing.T) {
	d := policy()
	c := newTest(t, d, "")
	ctx, done := begin(t, c, "alice", secretA)
	defer done()
	local, remote := net.Pipe()
	defer remote.Close()
	conn, err := Dial(ctx, func(context.Context) (net.Conn, error) { return local, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	reading := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := conn.Read(b[:])
		reading <- err
	}()
	d.Users[0].Disabled = true
	if err := c.Replace(d); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-reading:
		if err == nil {
			t.Fatal("revoked socket remained readable")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revocation did not unblock in-flight read")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		c.mu.Lock()
		active := c.accounts["a"].tunnels
		c.mu.Unlock()
		if active == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("revoked connection retained its admission slot")
		}
		time.Sleep(time.Millisecond)
	}

	// Revoking Alice must not revoke a different owner's connections.
	bob, finishBob := begin(t, c, "bob", secretB)
	defer finishBob()
	bobRaw := new(sink)
	bobConn, err := Dial(bob, func(context.Context) (net.Conn, error) {
		return bobRaw, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bobConn.Close()
	if _, err := bobConn.Write([]byte("bob-still-authorized")); err != nil {
		t.Fatalf("revocation spread to another user: %v", err)
	}
}

func TestStage2DialerErrorWithSocketClosesAndReleases(t *testing.T) {
	c := newTest(t, policy(), "")
	ctx, done := begin(t, c, "alice", secretA)
	defer done()
	raw := new(sink)
	conn, err := Dial(ctx, func(context.Context) (net.Conn, error) {
		return raw, errors.New("partial dial failure")
	})
	if err == nil || conn != nil || !raw.closed.Load() {
		t.Fatal("partial dial result must be closed and rejected")
	}
	conn, err = Dial(ctx, func(context.Context) (net.Conn, error) {
		return nil, nil
	})
	if !errors.Is(err, ErrDenied) || conn != nil {
		t.Fatal("nil connection accepted or admission leaked")
	}
	c.mu.Lock()
	active := c.accounts["a"].tunnels
	c.mu.Unlock()
	if active != 0 {
		t.Fatalf("failed dial retained %d sockets", active)
	}
}

func TestStage2DialContextIsNotStreamLifetime(t *testing.T) {
	c := newTest(t, policy(), "")
	requestCtx, done := begin(t, c, "alice", secretA)
	defer done()
	dialCtx, cancel := context.WithCancel(requestCtx)
	raw := new(sink)
	conn, err := Dial(dialCtx, func(context.Context) (net.Conn, error) {
		return raw, nil
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer conn.Close()
	cancel() // H2 CONNECT cancels its dialing timeout after the socket is open.
	if raw.closed.Load() {
		t.Fatal("dial timeout context closed established connection")
	}
	if _, err := conn.Write([]byte("still-authorized")); err != nil {
		t.Fatalf("dial context leaked into established stream: %v", err)
	}
}

func TestStage2PreCanceledDialDoesNotInvokeCallback(t *testing.T) {
	c := newTest(t, policy(), "")
	ctx, done := begin(t, c, "alice", secretA)
	defer done()
	pre, cancel := context.WithCancel(ctx)
	cancel()
	var started atomic.Bool
	conn, err := Dial(pre, func(context.Context) (net.Conn, error) {
		started.Store(true)
		return new(sink), nil
	})
	if !errors.Is(err, context.Canceled) || started.Load() || conn != nil {
		t.Fatal("pre-canceled request dialed destination")
	}
}
