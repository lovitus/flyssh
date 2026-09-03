package connector

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/flyssh/flyssh/internal/testkit"
	"golang.org/x/crypto/ssh"
)

func TestDialSingleHopAndExecute(t *testing.T) {
	server := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	host, portText, err := net.SplitHostPort(server.Addr)
	if err != nil {
		t.Fatalf("split SSH server address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse SSH server port: %v", err)
	}

	chain, err := Dial(context.Background(), Route{Hops: []Hop{{
		Host:        host,
		Port:        port,
		User:        "u1",
		Credentials: Credentials{Password: "p1"},
		HostKey:     HostKeyPolicy{ConfirmNew: func(string, string) bool { return true }},
	}}, Timeout: time.Second})
	if err != nil {
		t.Fatalf("dial connector: %v", err)
	}
	defer chain.Close()

	session, err := chain.Final().NewSession()
	if err != nil {
		t.Fatalf("new SSH session: %v", err)
	}
	defer session.Close()
	var output bytes.Buffer
	session.Stdout = &output
	if err := session.Run("printf connector-ok"); err != nil {
		t.Fatalf("run command through connector: %v", err)
	}
	if output.String() != "connector-ok" {
		t.Fatalf("unexpected connector output: %q", output.String())
	}
}

func TestPinnedHostKey(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
	callback, err := hostKeyCallback(HostKeyPolicy{PinnedSHA256: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("host:22", &net.TCPAddr{}, signer.PublicKey()); err != nil {
		t.Fatalf("pinned key rejected: %v", err)
	}
}

func TestPinnedHostKeyRejectsChange(t *testing.T) {
	_, privateA, _ := ed25519.GenerateKey(rand.Reader)
	_, privateB, _ := ed25519.GenerateKey(rand.Reader)
	signerA, _ := ssh.NewSignerFromKey(privateA)
	signerB, _ := ssh.NewSignerFromKey(privateB)
	callback, err := hostKeyCallback(HostKeyPolicy{PinnedSHA256: ssh.FingerprintSHA256(signerA.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("host:22", &net.TCPAddr{}, signerB.PublicKey()); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("changed key error = %v", err)
	}
}

func TestEmptyCredentialsRejected(t *testing.T) {
	if _, _, err := authMethods(Credentials{}); err == nil {
		t.Fatal("expected empty credentials to fail")
	}
}

func TestChainCloseClosesAgentResources(t *testing.T) {
	closed := false
	chain := &Chain{cleanup: []io.Closer{closeFunc(func() error {
		closed = true
		return nil
	})}}
	if err := chain.Close(); err != nil {
		t.Fatalf("chain close: %v", err)
	}
	if !closed {
		t.Fatal("chain close did not close agent resource")
	}
	if err := chain.Close(); err != nil {
		t.Fatalf("second chain close: %v", err)
	}
}

type closeFunc func() error

func (f closeFunc) Close() error { return f() }

func TestConfirmNewWithoutKnownHosts(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	key := signer.PublicKey()
	called := false
	callback, err := hostKeyCallback(HostKeyPolicy{ConfirmNew: func(host, fingerprint string) bool {
		called = host == "example:22" && fingerprint == ssh.FingerprintSHA256(key)
		return true
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("example:22", nil, key); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("confirmation was not called")
	}
}
