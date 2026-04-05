package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"net"
	"path/filepath"
	"testing"

	"github.com/flyssh/flyssh/pkg/cli"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestAutoAcceptHostKeyCallbackHandlesNilRemote(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	knownHostsFile := filepath.Join(t.TempDir(), "known_hosts")
	ensureKnownHostsFile(knownHostsFile)
	cb, err := knownhosts.New(knownHostsFile)
	if err != nil {
		t.Fatalf("knownhosts.New: %v", err)
	}

	wrapped := autoAcceptHostKeyCallback(cb, knownHostsFile, &cli.Options{}, true)
	if err := wrapped("example.test:22", nil, signer.PublicKey()); err != nil {
		t.Fatalf("wrapped callback returned error: %v", err)
	}

	check, err := knownhosts.New(knownHostsFile)
	if err != nil {
		t.Fatalf("knownhosts.New after save: %v", err)
	}
	if err := check("example.test:22", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}, signer.PublicKey()); err != nil {
		t.Fatalf("saved host key not accepted: %v", err)
	}
}
