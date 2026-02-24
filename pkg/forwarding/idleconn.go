package forwarding

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const DefaultIdleTimeout = 5 * time.Minute

// idleConn wraps a net.Conn and closes it if no Read/Write activity
// occurs for the configured timeout duration.
type idleConn struct {
	net.Conn
	lastActive atomic.Int64 // unix nanoseconds
	timeout    time.Duration
	closeOnce  sync.Once
	done       chan struct{}
}

func wrapIdleConn(conn net.Conn, timeout time.Duration) net.Conn {
	if timeout <= 0 {
		timeout = DefaultIdleTimeout
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
				ic.Conn.Close()
				return
			}
		}
	}
}
