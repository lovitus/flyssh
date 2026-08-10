package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/flyssh/flyssh/internal/testkit"
	"golang.org/x/crypto/ssh"
)

func TestParseGatewaySpec(t *testing.T) {
	user, password, bindAddr, err := parseGatewaySpec("admin:secret@127.0.0.1:2222")
	if err != nil {
		t.Fatalf("parseGatewaySpec returned error: %v", err)
	}
	if user != "admin" || password != "secret" || bindAddr != "127.0.0.1:2222" {
		t.Fatalf("unexpected parse result: user=%q password=%q bind=%q", user, password, bindAddr)
	}
}

func TestParseGatewaySpecRequiresPort(t *testing.T) {
	_, _, _, err := parseGatewaySpec("admin:secret@127.0.0.1")
	if err == nil {
		t.Fatal("expected missing port to fail")
	}
}

func TestParseGatewaySpecDoesNotUnescapePassword(t *testing.T) {
	_, password, _, err := parseGatewaySpec(`admin:p\@ss@127.0.0.1:2222`)
	if err != nil {
		t.Fatalf("parseGatewaySpec returned error: %v", err)
	}
	if password != `p\@ss` {
		t.Fatalf("password = %q, want current simple-parser behavior", password)
	}
}

func TestGatewayReadyInfoIncludesListenerAndHostKey(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}
	info, err := gatewayReadyInfo(listener, []ssh.Signer{signer})
	if err != nil {
		t.Fatalf("gatewayReadyInfo: %v", err)
	}
	if info.Address != listener.Addr().String() {
		t.Fatalf("address = %q, want %q", info.Address, listener.Addr())
	}
	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	wantPort, _ := strconv.Atoi(portText)
	if info.Port != wantPort {
		t.Fatalf("port = %d, want %d", info.Port, wantPort)
	}
	wantFingerprint := ssh.FingerprintSHA256(signer.PublicKey())
	if len(info.HostKeys) != 1 || info.HostKeys[0] != wantFingerprint {
		t.Fatalf("host keys = %#v, want %q", info.HostKeys, wantFingerprint)
	}
}

func TestServeWithReadyReportsPinnedGatewayAndProxiesExec(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configDir)
	t.Setenv("APPDATA", configDir)

	upstreamServer := testkit.StartSSHServer(t, map[string]string{"upstream": "secret"})
	upstream, err := ssh.Dial("tcp", upstreamServer.Addr, &ssh.ClientConfig{
		User:            "upstream",
		Auth:            []ssh.AuthMethod{ssh.Password("secret")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("dial upstream: %v", err)
	}
	t.Cleanup(func() { _ = upstream.Close() })

	readyCh := make(chan ReadyInfo, 1)
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- ServeWithReady(upstream, "local:password@127.0.0.1:0", false, func(info ReadyInfo) error {
			readyCh <- info
			return nil
		})
	}()

	var info ReadyInfo
	select {
	case info = <-readyCh:
	case <-time.After(15 * time.Second):
		t.Fatal("gateway readiness timed out")
	}
	if info.Port < 1 || len(info.HostKeys) == 0 {
		t.Fatalf("invalid readiness: %+v", info)
	}

	downstream, err := ssh.Dial("tcp", info.Address, &ssh.ClientConfig{
		User: "local",
		Auth: []ssh.AuthMethod{ssh.Password("password")},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fingerprint := ssh.FingerprintSHA256(key)
			if !slices.Contains(info.HostKeys, fingerprint) {
				return fmt.Errorf("unreported gateway host key %s", fingerprint)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer downstream.Close()

	session, err := downstream.NewSession()
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	command := "printf ready-proxy"
	wantOutput := "ready-proxy"
	if runtime.GOOS == "windows" {
		// The production proxy is portable; the test SSH server intentionally
		// relies on sh for command output, which is unavailable on stock Windows.
		command = ""
		wantOutput = ""
	}
	output, err := session.Output(command)
	if err != nil {
		t.Fatalf("exec through ready gateway: %v", err)
	}
	if string(output) != wantOutput {
		t.Fatalf("output = %q", output)
	}

	_ = upstream.Close()
	select {
	case <-serveErrCh:
	case <-time.After(5 * time.Second):
		t.Fatal("gateway did not stop after upstream closed")
	}
}

func TestGatewayExecReturnsOutputAfterStdinEOF(t *testing.T) {
	upstreamServer := testkit.StartSSHServer(t, map[string]string{"upstream": "secret"})
	upstream, err := ssh.Dial("tcp", upstreamServer.Addr, &ssh.ClientConfig{
		User:            "upstream",
		Auth:            []ssh.AuthMethod{ssh.Password("secret")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("dial upstream: %v", err)
	}
	t.Cleanup(func() { _ = upstream.Close() })

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate gateway host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("build gateway signer: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen gateway: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		_ = serveListener(listener, upstream, "local", "password", []ssh.Signer{signer}, false)
	}()

	downstream, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{
		User:            "local",
		Auth:            []ssh.AuthMethod{ssh.Password("password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { _ = downstream.Close() })

	session, err := downstream.NewSession()
	if err != nil {
		t.Fatalf("open gateway session: %v", err)
	}
	output, err := session.Output("printf gateway-output")
	if err != nil {
		t.Fatalf("run command through gateway: %v", err)
	}
	if got, want := string(output), "gateway-output"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}
