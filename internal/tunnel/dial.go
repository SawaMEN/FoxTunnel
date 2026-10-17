package tunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

type contextDial func(context.Context, string, string) (net.Conn, error)

// dialFamilies races address families, preserving resolver order within each.
// The second family starts after delay, or immediately if the first fails.
// Only two dial sequences run at once; every losing socket is closed.
func dialFamilies(ctx context.Context, ips []netip.Addr, port string, delay time.Duration, dial contextDial) (net.Conn, error) {
	if len(ips) == 0 {
		return nil, errors.New("no destination addresses")
	}
	var primary, fallback []netip.Addr
	for _, ip := range ips {
		if ip.Is4() == ips[0].Is4() {
			primary = append(primary, ip)
		} else {
			fallback = append(fallback, ip)
		}
	}
	serial := func(ctx context.Context, addresses []netip.Addr) (net.Conn, error) {
		var err error
		for _, ip := range addresses {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var c net.Conn
			c, err = dial(ctx, "tcp", net.JoinHostPort(ip.String(), port))
			if err == nil {
				return c, nil
			}
		}
		return nil, err
	}
	if len(fallback) == 0 {
		return serial(ctx, primary)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result)
	primaryFailed := make(chan struct{})
	run := func(addresses []netip.Addr, first bool) {
		if !first {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return
			case <-primaryFailed:
			case <-timer.C:
			}
		}
		conn, err := serial(ctx, addresses)
		if first && err != nil {
			close(primaryFailed)
		}
		select {
		case results <- result{conn, err}:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}
	go run(primary, true)
	go run(fallback, false)
	var errs []error
	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r := <-results:
			if r.err == nil {
				return r.conn, nil
			}
			errs = append(errs, r.err)
		}
	}
	return nil, errors.Join(errs...)
}
