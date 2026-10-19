//go:build neqo && cgo && linux && amd64

package neqo

import (
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"time"
)

func (c *connection) run() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	streams := make(map[uint64]*stream)
	var socket net.Conn
	var e *engine
	var reader sync.WaitGroup
	announced := false
	connected := false
	fatal := error(errClosed)
	announce := func(err error) {
		if !announced {
			c.readyErr = err
			announced = true
			close(c.ready)
		}
	}
	fail := func(s *stream, err error) {
		s.errorMu.Lock()
		if s.terminalError == nil {
			s.terminalError = err
		}
		s.errorMu.Unlock()
		if !s.headerSeen {
			s.headerSeen = true
			s.headers <- headerResult{err: err}
		}
		if s.pendingRead != nil {
			s.pendingRead.reply <- result{err: err}
			s.pendingRead = nil
		}
		if s.pendingSend != nil {
			s.pendingSend.reply <- result{err: err}
			s.pendingSend = nil
		}

		// A peer reset must also unblock an idle request-body Read. Do not
		// call Close synchronously: it joins the upload worker via this actor.
		go s.Close()
	}
	defer func() {
		if e != nil && socket != nil {
			e.shutdown()
			packet := make([]byte, 65535)
			socket.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
			for range 8 {
				n, _, err := e.output(packet)
				if err != nil || n == 0 {
					break
				}
				if _, err = socket.Write(packet[:n]); err != nil {
					break
				}
			}
		}
		c.cancel()
		if socket != nil {
			socket.Close()
		}
		reader.Wait()
		if e != nil {
			e.close()
		}
		announce(fatal)
		for _, s := range streams {
			fail(s, fatal)
		}
		close(c.done)
		c.owner.forget(c)
	}()
	setup, cancel := context.WithTimeout(c.ctx, c.owner.timeout)
	defer cancel()
	var err error
	socket, err = (&net.Dialer{}).DialContext(setup, "udp", c.addr)
	if err != nil {
		if c.ctx.Err() != nil {
			fatal = c.ctx.Err()
		} else {
			fatal = &ReachabilityError{Err: err}
		}
		return
	}
	settings := putFields(c.name, socket.LocalAddr().String(), socket.RemoteAddr().String())
	e, err = newEngine(settings)
	if err != nil {
		fatal = err
		return
	}
	packets := make(chan []byte, 8)
	readErrors := make(chan error, 1)
	reader.Go(func() {
		buffer := make([]byte, 65535)
		for {
			n, err := socket.Read(buffer)
			if err != nil {
				select {
				case readErrors <- err:
				default:
				}
				return
			}
			if n == 0 {
				continue
			}
			packet := append([]byte(nil), buffer[:n]...)
			select {
			case packets <- packet:
			case <-c.ctx.Done():
				return
			}
		}
	})
	deadline, _ := setup.Deadline()
	handshake := time.NewTimer(max(time.Nanosecond, time.Until(deadline)))
	defer handshake.Stop()
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	packetBuffer := make([]byte, 65535)
	metadata := make([]byte, maxMetadata)
	pumpRead := func(s *stream) error {
		cmd := s.pendingRead
		if cmd == nil {
			return nil
		}
		if s.recvFin {
			s.pendingRead = nil
			cmd.reply <- result{fin: true}
			return nil
		}
		n, fin, err := e.read(s.id, cmd.data)
		if err != nil {
			s.pendingRead = nil
			cmd.reply <- result{err: err}
			return err
		}
		if n > 0 || fin {
			s.pendingRead = nil
			s.recvFin = fin
			cmd.reply <- result{n: n, fin: fin}
		}
		return nil
	}
	pumpSend := func(s *stream) error {
		cmd := s.pendingSend
		if cmd == nil {
			return nil
		}
		for len(cmd.data) > 0 {
			n, err := e.send(s.id, cmd.data)
			if err != nil {
				s.pendingSend = nil
				cmd.reply <- result{err: err}
				return err
			}
			if n == 0 {
				return nil
			}
			cmd.data = cmd.data[n:]
		}
		s.pendingSend = nil
		cmd.reply <- result{}
		return nil
	}
	for {
		wait := time.Second
		for range 128 {
			n, ns, err := e.output(packetBuffer)
			if err != nil {
				fatal = err
				return
			}
			if n == 0 {
				wait = time.Duration(ns)
				break
			}
			socket.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := socket.Write(packetBuffer[:n]); err != nil {
				fatal = err
				if !connected {
					fatal = &ReachabilityError{Err: err}
				}
				return
			}
			wait = time.Nanosecond
		}
		events := false
		for range 256 {
			kind, id, arg, n, err := e.event(metadata)
			if err != nil {
				fatal = err
				return
			}
			if kind == 0 {
				break
			}
			events = true
			s := streams[id]
			switch kind {
			case 1:
				if err := c.verify(metadata[:n]); err != nil {
					fatal = err
					return
				}
				if err := e.authenticate(); err != nil {
					fatal = err
					return
				}
			case 2:
				c.tlsState.CipherSuite = uint16(arg)
				connected = true
				handshake.Stop()
				announce(nil)
			case 3:
				if s != nil {
					if err := s.response(metadata[:n], arg&1 != 0, arg&2 != 0); err != nil {
						e.reset(id)
						fail(s, err)
						delete(streams, id)
					}
				}
			case 4:
				if s != nil {
					if pumpRead(s) != nil {
						e.reset(id)
						fail(s, errProtocol)
						delete(streams, id)
					}
				}
			case 5:
				if s != nil {
					if pumpSend(s) != nil {
						e.reset(id)
						fail(s, errProtocol)
						delete(streams, id)
					}
				}
			case 6:
				if s != nil {
					fail(s, errClosed)
					delete(streams, id)
				}
			case 7:
				fatal = errClosed
				return
			case 8:
				// HTTP/3 GOAWAY is graceful drain, not a connection
				// error. Existing streams finish; new ones use a
				// separately authenticated QUIC connection.
				c.owner.retire(c)
			}
		}
		// Authentication and request creation can generate output without another
		// incoming datagram. Never park waiting for the next network input here.
		if events {
			wait = time.Nanosecond
		}
		timer.Reset(max(wait, time.Nanosecond))
		select {
		case <-c.ctx.Done():
			fatal = c.ctx.Err()
			return
		case <-handshake.C:
			if !connected {
				fatal = &ReachabilityError{Err: context.DeadlineExceeded}
				return
			}
		case <-timer.C:
		case err := <-readErrors:
			fatal = err
			if !connected {
				fatal = &ReachabilityError{Err: err}
			}
			return
		case packet := <-packets:
			if err := e.input(packet); err != nil {
				fatal = err
				return
			}
		case cmd := <-c.commands:
			s := cmd.stream
			if cmd.kind == 'o' {
				if err := s.req.Context().Err(); err != nil {
					cmd.reply <- result{err: err}
					continue
				}
				if c.draining.Load() {
					cmd.reply <- result{err: errDraining}
					continue
				}
				if !connected || len(streams) >= maxStreams {
					cmd.reply <- result{err: ErrCapacity}
					continue
				}
				id, err := e.fetch(cmd.data)
				if err != nil {
					cmd.reply <- result{err: err}
					continue
				}
				s.id = id
				streams[id] = s
				cmd.reply <- result{}
				continue
			}
			if streams[s.id] != s {
				cmd.reply <- result{err: errClosed}
				continue
			}
			switch cmd.kind {
			case 'w':
				if len(cmd.data) == 0 {
					cmd.reply <- result{}
					continue
				}
				if s.pendingSend != nil {
					cmd.reply <- result{err: errProtocol}
					continue
				}
				s.pendingSend = &cmd
				if pumpSend(s) != nil {
					e.reset(s.id)
					fail(s, errProtocol)
					delete(streams, s.id)
				}
			case 'r':
				if s.pendingRead != nil {
					cmd.reply <- result{err: errProtocol}
					continue
				}
				s.pendingRead = &cmd
				if pumpRead(s) != nil {
					e.reset(s.id)
					fail(s, errProtocol)
					delete(streams, s.id)
				}
			case 'f':
				err := e.fin(s.id)
				cmd.reply <- result{err: err}
				if err != nil {
					fail(s, err)
					delete(streams, s.id)
				}
			case 'x':
				e.reset(s.id)
				fail(s, errClosed)
				delete(streams, s.id)
				cmd.reply <- result{}
			default:
				cmd.reply <- result{err: errProtocol}
			}
		}
	}
}

// Assert that all request bodies follow the net/http close-to-unblock contract.
var _ io.ReadCloser = (*stream)(nil)
