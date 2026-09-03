package socks

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/flyssh/flyssh/internal/testkit"
)

func TestDialViaSocks5ContextCancellationClosesHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen SOCKS stub: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = DialViaSocks5Context(ctx, listener.Addr().String(), "127.0.0.1:1", "", "")
	if err == nil {
		t.Fatal("expected cancelled SOCKS handshake to fail")
	}

	select {
	case conn := <-accepted:
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, readErr := conn.Read(make([]byte, 64)); readErr != nil {
			t.Fatalf("read SOCKS greeting: %v", readErr)
		}
		_, readErr := conn.Read(make([]byte, 1))
		if readErr == nil {
			t.Fatal("SOCKS handshake connection remained open after cancellation")
		}
		if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
			t.Fatalf("SOCKS handshake connection was not closed after cancellation: %v", readErr)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS stub did not accept the connection")
	}
}

func TestDialViaSocks5_NoAuth(t *testing.T) {
	echoAddr := testkit.StartTCPEchoServer(t)
	proxy := testkit.StartSOCKS5Proxy(t, "", "")

	conn, err := DialViaSocks5(proxy.Addr, echoAddr, "", "")
	if err != nil {
		t.Fatalf("dial via socks5: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("unexpected echo: %q", string(buf))
	}
}

func TestDialViaSocks5_UserPassAuth(t *testing.T) {
	echoAddr := testkit.StartTCPEchoServer(t)
	proxy := testkit.StartSOCKS5Proxy(t, "u1", "p1")

	conn, err := DialViaSocks5(proxy.Addr, echoAddr, "u1", "p1")
	if err != nil {
		t.Fatalf("dial via socks5 with auth: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("ok")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ok" {
		t.Fatalf("unexpected echo: %q", string(buf))
	}
}

func TestDialViaSocks5_BadPassword(t *testing.T) {
	echoAddr := testkit.StartTCPEchoServer(t)
	proxy := testkit.StartSOCKS5Proxy(t, "u1", "p1")

	_, err := DialViaSocks5(proxy.Addr, echoAddr, "u1", "wrong")
	if err == nil {
		t.Fatalf("expected auth failure, got nil")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected authentication failed error, got: %v", err)
	}
}
