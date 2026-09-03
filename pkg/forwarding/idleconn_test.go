package forwarding

import (
	"io"
	"net"
	"testing"
	"time"
)

type closeWriteTestConn struct {
	closeWriteCount int
}

func (c *closeWriteTestConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *closeWriteTestConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *closeWriteTestConn) Close() error                     { return nil }
func (c *closeWriteTestConn) LocalAddr() net.Addr              { return nil }
func (c *closeWriteTestConn) RemoteAddr() net.Addr             { return nil }
func (c *closeWriteTestConn) SetDeadline(time.Time) error      { return nil }
func (c *closeWriteTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *closeWriteTestConn) SetWriteDeadline(time.Time) error { return nil }
func (c *closeWriteTestConn) CloseWrite() error {
	c.closeWriteCount++
	return nil
}

func TestIdleConnCloseWritePassesThrough(t *testing.T) {
	base := &closeWriteTestConn{}
	conn := wrapIdleConn(base, time.Minute)
	t.Cleanup(func() { _ = conn.Close() })

	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("wrapped idle connection does not expose CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite returned error: %v", err)
	}
	if base.closeWriteCount != 1 {
		t.Fatalf("CloseWrite count = %d, want 1", base.closeWriteCount)
	}
}

func TestDefaultIdleTimeoutDoesNotWrapConnection(t *testing.T) {
	base := &closeWriteTestConn{}
	got := wrapIdleConn(base, DefaultIdleTimeout)
	if got != base {
		t.Fatalf("default idle timeout wrapped connection: got %T, want original %T", got, base)
	}
}
