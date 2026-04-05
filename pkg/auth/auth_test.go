package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"net"
	"os"
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

func TestAutoAcceptHostKeyCallbackConfirmsChangedKeyViaPromptInput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate old rsa key: %v", err)
	}
	oldSigner, err := ssh.NewSignerFromKey(oldKey)
	if err != nil {
		t.Fatalf("new old signer: %v", err)
	}

	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate new rsa key: %v", err)
	}
	newSigner, err := ssh.NewSignerFromKey(newKey)
	if err != nil {
		t.Fatalf("new new signer: %v", err)
	}

	knownHostsFile := filepath.Join(t.TempDir(), "known_hosts")
	ensureKnownHostsFile(knownHostsFile)
	saveHostKey(knownHostsFile, "example.test:22", oldSigner.PublicKey())

	cb, err := knownhosts.New(knownHostsFile)
	if err != nil {
		t.Fatalf("knownhosts.New: %v", err)
	}

	inputFile := filepath.Join(t.TempDir(), "prompt.txt")
	if err := os.WriteFile(inputFile, []byte("confirm fingerprint changed\n"), 0o600); err != nil {
		t.Fatalf("write prompt input: %v", err)
	}

	oldOpener := promptInputOpener
	promptInputOpener = func() (*os.File, func(), error) {
		f, err := os.Open(inputFile)
		if err != nil {
			return nil, nil, err
		}
		return f, func() { _ = f.Close() }, nil
	}
	defer func() { promptInputOpener = oldOpener }()

	wrapped := autoAcceptHostKeyCallback(cb, knownHostsFile, &cli.Options{}, true)
	if err := wrapped("example.test:22", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}, newSigner.PublicKey()); err != nil {
		t.Fatalf("wrapped callback returned error: %v", err)
	}

	check, err := knownhosts.New(knownHostsFile)
	if err != nil {
		t.Fatalf("knownhosts.New after update: %v", err)
	}
	if err := check("example.test:22", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}, newSigner.PublicKey()); err != nil {
		t.Fatalf("updated host key not accepted: %v", err)
	}

	data, err := os.ReadFile(knownHostsFile)
	if err != nil {
		t.Fatalf("read known_hosts after update: %v", err)
	}
	if string(data) == "" {
		t.Fatal("expected known_hosts to contain updated key")
	}
}
