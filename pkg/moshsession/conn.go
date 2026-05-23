package moshsession

import (
	"net"
	"os"
	"sync"
	"time"
)

type tunnelConn struct {
	mu       sync.Mutex
	readCh   chan []byte
	writeCh  chan []byte
	closed   chan struct{}
	deadline time.Time
}

func newTunnelConn() *tunnelConn {
	return &tunnelConn{
		readCh:  make(chan []byte, 256),
		writeCh: make(chan []byte, 256),
		closed:  make(chan struct{}),
	}
}

func (c *tunnelConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()
	var timer <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		timer = time.After(d)
	}
	select {
	case payload := <-c.readCh:
		return copy(p, payload), nil
	case <-timer:
		return 0, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *tunnelConn) Write(p []byte) (int, error) {
	payload := append([]byte(nil), p...)
	select {
	case c.writeCh <- payload:
	default:
	}
	return len(p), nil
}

func (c *tunnelConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *tunnelConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *tunnelConn) deliver(payload []byte) bool {
	payload = append([]byte(nil), payload...)
	select {
	case c.readCh <- payload:
		return true
	case <-c.closed:
		return false
	}
}
