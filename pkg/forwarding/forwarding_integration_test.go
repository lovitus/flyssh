package forwarding

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/flyssh/flyssh/internal/testkit"
	"github.com/flyssh/flyssh/pkg/socks"
	"golang.org/x/crypto/ssh"
)

func TestStartLocalForward(t *testing.T) {
	echoAddr := testkit.StartTCPEchoServer(t)
	sshSrv := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTestSSH(t, sshSrv.Addr, "u1", "p1")
	defer client.Close()

	port := freePort(t)
	spec := fmt.Sprintf("127.0.0.1:%d:%s", port, echoAddr)

	errCh := make(chan error, 1)
	go func() { errCh <- StartLocalForward(client, spec, false) }()

	bindAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if err := testkit.WaitForTCP(bindAddr, 2*time.Second); err != nil {
		t.Fatalf("local forward not ready: %v", err)
	}

	c, err := net.DialTimeout("tcp", bindAddr, time.Second)
	if err != nil {
		t.Fatalf("dial local forward: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("unexpected echo: %q", string(buf))
	}

	_ = client.Close()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("local forward goroutine did not exit")
	}
}

func TestStartDynamicForward(t *testing.T) {
	echoAddr := testkit.StartTCPEchoServer(t)
	sshSrv := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTestSSH(t, sshSrv.Addr, "u1", "p1")
	defer client.Close()

	port := freePort(t)
	spec := fmt.Sprintf("127.0.0.1:%d", port)

	errCh := make(chan error, 1)
	go func() { errCh <- StartDynamicForward(client, spec, false) }()

	bindAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if err := testkit.WaitForTCP(bindAddr, 2*time.Second); err != nil {
		t.Fatalf("dynamic forward not ready: %v", err)
	}

	conn, err := socks.DialViaSocks5(bindAddr, echoAddr, "", "")
	if err != nil {
		t.Fatalf("dial dynamic socks5: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write([]byte("dyn")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "dyn" {
		t.Fatalf("unexpected echo: %q", string(buf))
	}

	_ = client.Close()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("dynamic forward goroutine did not exit")
	}
}

func TestStartRemoteForward(t *testing.T) {
	localEcho := testkit.StartTCPEchoServer(t)
	sshSrv := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTestSSH(t, sshSrv.Addr, "u1", "p1")
	defer client.Close()

	remotePort := freePort(t)
	spec := fmt.Sprintf("127.0.0.1:%d:%s", remotePort, localEcho)

	errCh := make(chan error, 1)
	go func() { errCh <- StartRemoteForward(client, spec, false) }()

	remoteAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort))
	if err := testkit.WaitForTCP(remoteAddr, 2*time.Second); err != nil {
		t.Fatalf("remote forward not ready: %v", err)
	}

	c, err := net.DialTimeout("tcp", remoteAddr, time.Second)
	if err != nil {
		t.Fatalf("dial remote forwarded port: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := c.Write([]byte("rmt")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "rmt" {
		t.Fatalf("unexpected echo: %q", string(buf))
	}

	_ = client.Close()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("remote forward goroutine did not exit")
	}
}

func TestStartLocalForward_Multiple(t *testing.T) {
	sshSrv := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTestSSH(t, sshSrv.Addr, "u1", "p1")
	defer client.Close()

	echo1 := testkit.StartTCPEchoServer(t)
	echo2 := testkit.StartTCPEchoServer(t)
	p1 := freePort(t)
	p2 := freePort(t)

	spec1 := fmt.Sprintf("127.0.0.1:%d:%s", p1, echo1)
	spec2 := fmt.Sprintf("127.0.0.1:%d:%s", p2, echo2)

	err1 := make(chan error, 1)
	err2 := make(chan error, 1)
	go func() { err1 <- StartLocalForward(client, spec1, false) }()
	go func() { err2 <- StartLocalForward(client, spec2, false) }()

	addr1 := net.JoinHostPort("127.0.0.1", strconv.Itoa(p1))
	addr2 := net.JoinHostPort("127.0.0.1", strconv.Itoa(p2))
	if err := testkit.WaitForTCP(addr1, 2*time.Second); err != nil {
		t.Fatalf("local forward #1 not ready: %v", err)
	}
	if err := testkit.WaitForTCP(addr2, 2*time.Second); err != nil {
		t.Fatalf("local forward #2 not ready: %v", err)
	}

	assertEcho(t, addr1, "l1")
	assertEcho(t, addr2, "l2")

	_ = client.Close()
	waitForwardExit(t, err1, "local forward #1")
	waitForwardExit(t, err2, "local forward #2")
}

func TestStartRemoteForward_Multiple(t *testing.T) {
	sshSrv := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTestSSH(t, sshSrv.Addr, "u1", "p1")
	defer client.Close()

	localEcho1 := testkit.StartTCPEchoServer(t)
	localEcho2 := testkit.StartTCPEchoServer(t)
	rp1 := freePort(t)
	rp2 := freePort(t)

	spec1 := fmt.Sprintf("127.0.0.1:%d:%s", rp1, localEcho1)
	spec2 := fmt.Sprintf("127.0.0.1:%d:%s", rp2, localEcho2)

	err1 := make(chan error, 1)
	err2 := make(chan error, 1)
	go func() { err1 <- StartRemoteForward(client, spec1, false) }()
	go func() { err2 <- StartRemoteForward(client, spec2, false) }()

	addr1 := net.JoinHostPort("127.0.0.1", strconv.Itoa(rp1))
	addr2 := net.JoinHostPort("127.0.0.1", strconv.Itoa(rp2))
	if err := testkit.WaitForTCP(addr1, 2*time.Second); err != nil {
		t.Fatalf("remote forward #1 not ready: %v", err)
	}
	if err := testkit.WaitForTCP(addr2, 2*time.Second); err != nil {
		t.Fatalf("remote forward #2 not ready: %v", err)
	}

	assertEcho(t, addr1, "r1")
	assertEcho(t, addr2, "r2")

	_ = client.Close()
	waitForwardExit(t, err1, "remote forward #1")
	waitForwardExit(t, err2, "remote forward #2")
}

func TestStartDynamicForward_Multiple(t *testing.T) {
	sshSrv := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTestSSH(t, sshSrv.Addr, "u1", "p1")
	defer client.Close()

	echo1 := testkit.StartTCPEchoServer(t)
	echo2 := testkit.StartTCPEchoServer(t)
	p1 := freePort(t)
	p2 := freePort(t)
	spec1 := fmt.Sprintf("127.0.0.1:%d", p1)
	spec2 := fmt.Sprintf("127.0.0.1:%d", p2)

	err1 := make(chan error, 1)
	err2 := make(chan error, 1)
	go func() { err1 <- StartDynamicForward(client, spec1, false) }()
	go func() { err2 <- StartDynamicForward(client, spec2, false) }()

	addr1 := net.JoinHostPort("127.0.0.1", strconv.Itoa(p1))
	addr2 := net.JoinHostPort("127.0.0.1", strconv.Itoa(p2))
	if err := testkit.WaitForTCP(addr1, 2*time.Second); err != nil {
		t.Fatalf("dynamic forward #1 not ready: %v", err)
	}
	if err := testkit.WaitForTCP(addr2, 2*time.Second); err != nil {
		t.Fatalf("dynamic forward #2 not ready: %v", err)
	}

	assertSOCKSEcho(t, addr1, echo1, "d1")
	assertSOCKSEcho(t, addr2, echo2, "d2")

	_ = client.Close()
	waitForwardExit(t, err1, "dynamic forward #1")
	waitForwardExit(t, err2, "dynamic forward #2")
}

func TestMixedForwards_Concurrent(t *testing.T) {
	sshSrv := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTestSSH(t, sshSrv.Addr, "u1", "p1")
	defer client.Close()

	localEcho := testkit.StartTCPEchoServer(t)
	remoteEcho := testkit.StartTCPEchoServer(t)
	dynEcho := testkit.StartTCPEchoServer(t)

	localPort := freePort(t)
	remotePort := freePort(t)
	dynPort := freePort(t)

	lSpec := fmt.Sprintf("127.0.0.1:%d:%s", localPort, localEcho)
	rSpec := fmt.Sprintf("127.0.0.1:%d:%s", remotePort, remoteEcho)
	dSpec := fmt.Sprintf("127.0.0.1:%d", dynPort)

	lErr := make(chan error, 1)
	rErr := make(chan error, 1)
	dErr := make(chan error, 1)
	go func() { lErr <- StartLocalForward(client, lSpec, false) }()
	go func() { rErr <- StartRemoteForward(client, rSpec, false) }()
	go func() { dErr <- StartDynamicForward(client, dSpec, false) }()

	lAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort))
	rAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort))
	dAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(dynPort))
	if err := testkit.WaitForTCP(lAddr, 2*time.Second); err != nil {
		t.Fatalf("local forward not ready: %v", err)
	}
	if err := testkit.WaitForTCP(rAddr, 2*time.Second); err != nil {
		t.Fatalf("remote forward not ready: %v", err)
	}
	if err := testkit.WaitForTCP(dAddr, 2*time.Second); err != nil {
		t.Fatalf("dynamic forward not ready: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(3)
		i := i
		go func() {
			defer wg.Done()
			assertEcho(t, lAddr, fmt.Sprintf("L-%d", i))
		}()
		go func() {
			defer wg.Done()
			assertEcho(t, rAddr, fmt.Sprintf("R-%d", i))
		}()
		go func() {
			defer wg.Done()
			assertSOCKSEcho(t, dAddr, dynEcho, fmt.Sprintf("D-%d", i))
		}()
	}
	wg.Wait()

	_ = client.Close()
	waitForwardExit(t, lErr, "mixed local forward")
	waitForwardExit(t, rErr, "mixed remote forward")
	waitForwardExit(t, dErr, "mixed dynamic forward")
}

func dialTestSSH(t *testing.T, addr, user, pass string) *ssh.Client {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("ssh dial %s: %v", addr, err)
	}
	return c
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("alloc free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitForwardExit(t *testing.T, errCh <-chan error, name string) {
	t.Helper()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s goroutine did not exit", name)
	}
}

func assertEcho(t *testing.T, addr, msg string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("write %s: %v", addr, err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read %s: %v", addr, err)
	}
	if string(buf) != msg {
		t.Fatalf("unexpected echo from %s: want %q got %q", addr, msg, string(buf))
	}
}

func assertSOCKSEcho(t *testing.T, socksAddr, targetAddr, msg string) {
	t.Helper()
	conn, err := socks.DialViaSocks5(socksAddr, targetAddr, "", "")
	if err != nil {
		t.Fatalf("dial via socks %s -> %s: %v", socksAddr, targetAddr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write via socks: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read via socks: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("unexpected socks echo: want %q got %q", msg, string(buf))
	}
}
