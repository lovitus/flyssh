package socks

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/flyssh/flyssh/internal/testkit"
)

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
