package forwarding

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultIdleTimeout disables the forwarding connection watchdog. Forwarding
// connections are closed with their owning SSH client or when either side of
// the copy finishes, matching normal SSH forwarding semantics.
const DefaultIdleTimeout time.Duration = 0

// idleConn wraps a net.Conn and closes it if no Read/Write activity
// occurs for the configured timeout duration.
type idleConn struct {
	net.Conn
	lastActive atomic.Int64 // unix nanoseconds
	timeout    time.Duration
	closeOnce  sync.Once
	done       chan struct{}
}

type closeWriter interface {
	CloseWrite() error
}

func wrapIdleConn(conn net.Conn, timeout time.Duration) net.Conn {
	if timeout <= 0 {
		return conn
	}
	ic := &idleConn{
		Conn:    conn,
		timeout: timeout,
		done:    make(chan struct{}),
	}
	ic.touch()
	go ic.watchdog()
	return ic
}

func (ic *idleConn) touch() {
	ic.lastActive.Store(time.Now().UnixNano())
}

func (ic *idleConn) Read(b []byte) (int, error) {
	n, err := ic.Conn.Read(b)
	if n > 0 {
		ic.touch()
	}
	return n, err
}

func (ic *idleConn) Write(b []byte) (int, error) {
	n, err := ic.Conn.Write(b)
	if n > 0 {
		ic.touch()
	}
	return n, err
}

func (ic *idleConn) Close() error {
	ic.closeOnce.Do(func() { close(ic.done) })
	return ic.Conn.Close()
}

func (ic *idleConn) CloseWrite() error {
	ic.touch()
	if cw, ok := ic.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (ic *idleConn) watchdog() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ic.done:
			return
		case <-ticker.C:
			last := time.Unix(0, ic.lastActive.Load())
			if time.Since(last) > ic.timeout {
				log.Printf("flyssh: idle forwarding connection closed after %s", ic.timeout)
				ic.Conn.Close()
				return
			}
		}
	}
}
