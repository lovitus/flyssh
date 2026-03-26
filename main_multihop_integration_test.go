package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/flyssh/flyssh/internal/testkit"
	"github.com/flyssh/flyssh/pkg/cli"
	"github.com/flyssh/flyssh/pkg/config"
	"github.com/flyssh/flyssh/pkg/forwarding"
	"github.com/flyssh/flyssh/pkg/socks"
	"golang.org/x/crypto/ssh"
)

func TestConnectHop_MultiHopViaDirectTCPIP(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	first := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	second := testkit.StartSSHServer(t, map[string]string{"u2": "p2"})

	firstClient := dialSSHForMainTest(t, first.Addr, "u1", "p1")
	defer firstClient.Close()

	host, portStr, err := net.SplitHostPort(second.Addr)
	if err != nil {
		t.Fatalf("split second addr: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	hop := cli.HopSpec{
		User:     "u2",
		Password: "p2",
		Host:     host,
		Port:     port,
	}
	opts := &cli.Options{}

	secondClient, err := connectHop(firstClient, hop, opts, 2)
	if err != nil {
		t.Fatalf("connect hop: %v", err)
	}
	defer secondClient.Close()

	sess, err := secondClient.NewSession()
	if err != nil {
		t.Fatalf("new session on second hop: %v", err)
	}
	defer sess.Close()

	var out bytes.Buffer
	sess.Stdout = &out
	if err := sess.Run("printf 'ok'"); err != nil {
		t.Fatalf("run command on second hop: %v", err)
	}
	if out.String() != "ok" {
		t.Fatalf("unexpected command output: %q", out.String())
	}
}

func dialSSHForMainTest(t *testing.T, addr, user, pass string) *ssh.Client {
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

func TestMultiHopWithSOCKSAndMixedForwards(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	first := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	second := testkit.StartSSHServer(t, map[string]string{"u2": "p2"})
	proxy := testkit.StartSOCKS5Proxy(t, "", "")

	firstHost, firstPortStr, err := net.SplitHostPort(first.Addr)
	if err != nil {
		t.Fatalf("split first addr: %v", err)
	}
	firstPort, _ := strconv.Atoi(firstPortStr)

	opts := &cli.Options{
		Password:      "p1",
		SocksProxy:    proxy.Addr,
		ReconnectDelay: 1,
	}

	cfg := &config.ResolvedConfig{
		User:           "u1",
		Hostname:       firstHost,
		Port:           firstPort,
		ConnectTimeout: 5 * time.Second,
		SocksProxy:     proxy.Addr,
		SocksUser:      "",
		SocksPassword:  "",
		KnownHostsFile: t.TempDir() + "/known_hosts",
	}

	firstClient, err := connectFirstHost(cfg, opts)
	if err != nil {
		t.Fatalf("connect first host via socks: %v", err)
	}
	defer firstClient.Close()

	secondHost, secondPortStr, err := net.SplitHostPort(second.Addr)
	if err != nil {
		t.Fatalf("split second addr: %v", err)
	}
	secondPort, _ := strconv.Atoi(secondPortStr)

	hop := cli.HopSpec{
		User:     "u2",
		Password: "p2",
		Host:     secondHost,
		Port:     secondPort,
	}
	secondClient, err := connectHop(firstClient, hop, opts, 2)
	if err != nil {
		t.Fatalf("connect second hop: %v", err)
	}
	defer secondClient.Close()

	localEcho := testkit.StartTCPEchoServer(t)
	remoteEcho := testkit.StartTCPEchoServer(t)
	dynEcho := testkit.StartTCPEchoServer(t)

	localPort := freeMainPort(t)
	remotePort := freeMainPort(t)
	dynPort := freeMainPort(t)

	lSpec := fmt.Sprintf("127.0.0.1:%d:%s", localPort, localEcho)
	rSpec := fmt.Sprintf("127.0.0.1:%d:%s", remotePort, remoteEcho)
	dSpec := fmt.Sprintf("127.0.0.1:%d", dynPort)

	lErr := make(chan error, 1)
	rErr := make(chan error, 1)
	dErr := make(chan error, 1)
	go func() { lErr <- forwarding.StartLocalForward(secondClient, lSpec, false) }()
	go func() { rErr <- forwarding.StartRemoteForward(secondClient, rSpec, false) }()
	go func() { dErr <- forwarding.StartDynamicForward(secondClient, dSpec, false) }()

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

	assertMainEcho(t, lAddr, "mh-l")
	assertMainEcho(t, rAddr, "mh-r")
	assertMainSOCKSEcho(t, dAddr, dynEcho, "mh-d")

	_ = secondClient.Close()
	waitMainForwardExit(t, lErr, "multihop local")
	waitMainForwardExit(t, rErr, "multihop remote")
	waitMainForwardExit(t, dErr, "multihop dynamic")
}

func freeMainPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("alloc port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitMainForwardExit(t *testing.T, errCh <-chan error, name string) {
	t.Helper()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not exit", name)
	}
}

func assertMainEcho(t *testing.T, addr, msg string) {
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

func assertMainSOCKSEcho(t *testing.T, socksAddr, targetAddr, msg string) {
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
