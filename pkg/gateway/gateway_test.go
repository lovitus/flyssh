package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"net"
	"testing"

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
