//go:build !windows

package e2e_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/flyssh/flyssh/internal/testkit"
)

const e2eEnv = "FLYSSH_E2E"

var (
	buildOnce sync.Once
	buildPath string
	buildErr  error
)

func TestInteractivePasswordReconnectRestoresForward(t *testing.T) {
	requireE2E(t)
	sshServer := testkit.StartSSHServer(t, map[string]string{"user": "password"})
	echoAddr := testkit.StartTCPEchoServer(t)
	proxy := newCuttableSOCKS(t)

	localPort := freePort(t)
	command, terminal, output := startFlySSHPTY(t,
		"user@"+sshServer.Addr,
		"--socks", proxy.Addr(),
		"-L", fmt.Sprintf("127.0.0.1:%d:%s", localPort, echoAddr),
		"-N",
		"--reconnect-delay", "1",
	)
	defer stopCommand(command, terminal)

	waitForOutput(t, output, "password:", 10*time.Second)
	if _, err := terminal.Write([]byte("password\n")); err != nil {
		t.Fatalf("write initial password: %v", err)
	}
	waitForOutput(t, output, "Local forward:", 10*time.Second)
	assertEcho(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)), "before-drop")

	proxy.Drop()
	waitForOutput(t, output, "reconnect attempt #1 in 1s", 10*time.Second)
	waitForOccurrences(t, output, "Local forward:", 2, 10*time.Second)
	waitForEcho(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)), "after-drop", 10*time.Second)

	if got := strings.Count(output.String(), "password:"); got != 1 {
		t.Fatalf("password prompt count = %d, want 1; output:\n%s", got, output.String())
	}
}

func TestForwardConnectionSurvivesLegacyIdleWindow(t *testing.T) {
	requireE2E(t)
	sshServer := testkit.StartSSHServer(t, map[string]string{"user": "password"})
	echoAddr := testkit.StartTCPEchoServer(t)
	localPort := freePort(t)
	command, terminal, output := startFlySSHPTY(t,
		"user:password@"+sshServer.Addr,
		"-L", fmt.Sprintf("127.0.0.1:%d:%s", localPort, echoAddr),
		"-N",
		"--no-reconnect",
	)
	defer stopCommand(command, terminal)
	waitForOutput(t, output, "Local forward:", 10*time.Second)

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)), 5*time.Second)
	if err != nil {
		t.Fatalf("dial forwarded echo: %v", err)
	}
	defer conn.Close()

	// Five minutes was the old FlySSH forwarding watchdog. Do not write any
	// application bytes during this interval; after it expires, the same TCP
	// connection must still carry a complete echo round trip.
	time.Sleep(5*time.Minute + 10*time.Second)
	if _, err := conn.Write([]byte("idle-window")); err != nil {
		t.Fatalf("write after legacy idle window: %v; output:\n%s", err, output.String())
	}
	buf := make([]byte, len("idle-window"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read after legacy idle window: %v; output:\n%s", err, output.String())
	}
	if string(buf) != "idle-window" {
		t.Fatalf("echo after legacy idle window = %q", buf)
	}
}

func requireE2E(t *testing.T) {
	t.Helper()
	if os.Getenv(e2eEnv) != "1" {
		t.Skipf("set %s=1 to run subprocess reconnect E2E tests", e2eEnv)
	}
}

func flySSHBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		root, err := filepath.Abs("..")
		if err != nil {
			buildErr = err
			return
		}
		buildPath = filepath.Join(os.TempDir(), "flyssh-e2e-bin")
		build := exec.Command("go", "build", "-o", buildPath, ".")
		build.Dir = root
		build.Env = os.Environ()
		if output, err := build.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("build flyssh E2E binary: %w\n%s", err, output)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return buildPath
}

func startFlySSHPTY(t *testing.T, args ...string) (*exec.Cmd, *os.File, *lockedBuffer) {
	t.Helper()
	command := exec.Command(flySSHBinary(t), args...)
	command.Env = append(os.Environ(), "HOME="+t.TempDir())
	terminal, err := pty.Start(command)
	if err != nil {
		t.Fatalf("start flyssh E2E process: %v", err)
	}
	output := &lockedBuffer{}
	go func() { _, _ = io.Copy(output, terminal) }()
	return command, terminal, output
}

func stopCommand(command *exec.Cmd, terminal *os.File) {
	_ = terminal.Close()
	if command.Process != nil {
		_ = command.Process.Kill()
	}
	_, _ = command.Process.Wait()
}

func waitForOutput(t *testing.T, output *lockedBuffer, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(output.String(), want) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q; output:\n%s", want, output.String())
}

func waitForOccurrences(t *testing.T, output *lockedBuffer, want string, count int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Count(output.String(), want) >= count {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d %q entries; output:\n%s", count, want, output.String())
}

func assertEcho(t *testing.T, address, payload string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write echo payload: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo payload: %v", err)
	}
	if string(buf) != payload {
		t.Fatalf("echo payload = %q, want %q", buf, payload)
	}
}

func waitForEcho(t *testing.T, address, payload string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			_, writeErr := conn.Write([]byte(payload))
			buf := make([]byte, len(payload))
			_, readErr := io.ReadFull(conn, buf)
			_ = conn.Close()
			if writeErr == nil && readErr == nil && string(buf) == payload {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("forward %s did not recover within %s", address, timeout)
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	n, err := b.buf.Write(data)
	b.mu.Unlock()
	return n, err
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	value := b.buf.String()
	b.mu.Unlock()
	return value
}

type cuttableSOCKS struct {
	listener net.Listener
	mu       sync.Mutex
	upstream map[net.Conn]struct{}
}

func newCuttableSOCKS(t *testing.T) *cuttableSOCKS {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen SOCKS proxy: %v", err)
	}
	proxy := &cuttableSOCKS{listener: listener, upstream: make(map[net.Conn]struct{})}
	go proxy.acceptLoop()
	t.Cleanup(func() {
		_ = listener.Close()
		proxy.Drop()
	})
	return proxy
}

func (p *cuttableSOCKS) Addr() string { return p.listener.Addr().String() }

func (p *cuttableSOCKS) Drop() {
	p.mu.Lock()
	connections := make([]net.Conn, 0, len(p.upstream))
	for conn := range p.upstream {
		connections = append(connections, conn)
	}
	p.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func (p *cuttableSOCKS) acceptLoop() {
	for {
		client, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(client)
	}
}

func (p *cuttableSOCKS) handle(client net.Conn) {
	defer client.Close()
	if err := socksHandshake(client); err != nil {
		return
	}
	target, err := socksTarget(client)
	if err != nil {
		return
	}
	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	p.mu.Lock()
	p.upstream[upstream] = struct{}{}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.upstream, upstream)
		p.mu.Unlock()
	}()
	_, _ = client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	copyDone := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); copyDone <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); copyDone <- struct{}{} }()
	<-copyDone
}

func socksHandshake(client net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(client, header); err != nil || header[0] != 5 {
		return fmt.Errorf("read greeting: %w", err)
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return err
	}
	for _, method := range methods {
		if method == 0 {
			_, err := client.Write([]byte{5, 0})
			return err
		}
	}
	_, _ = client.Write([]byte{5, 255})
	return fmt.Errorf("no no-auth SOCKS method")
}

func socksTarget(client net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(client, header); err != nil {
		return "", err
	}
	if header[0] != 5 || header[1] != 1 || header[2] != 0 {
		return "", fmt.Errorf("invalid CONNECT request")
	}
	var host string
	switch header[3] {
	case 1:
		address := make([]byte, 4)
		if _, err := io.ReadFull(client, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(client, size[:]); err != nil {
			return "", err
		}
		name := make([]byte, int(size[0]))
		if _, err := io.ReadFull(client, name); err != nil {
			return "", err
		}
		host = string(name)
	case 4:
		address := make([]byte, 16)
		if _, err := io.ReadFull(client, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	default:
		return "", fmt.Errorf("unsupported address type %d", header[3])
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(client, portBytes[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(portBytes[0])<<8|int(portBytes[1]))), nil
}
