package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestPromptBrokerProvidesPromptInput(t *testing.T) {
	oldLineReader := localPromptLineReader
	oldPasswordReader := localPromptPasswordReader
	oldBrokerLineReader := brokerPromptLineReader
	oldBrokerPasswordReader := brokerPromptPasswordReader
	localPromptLineReader = func() (string, error) { return "line-answer", nil }
	localPromptPasswordReader = func() ([]byte, error) { return []byte("secret-answer"), nil }
	brokerPromptLineReader = func(cancel <-chan struct{}) (string, error) { return "line-answer", nil }
	brokerPromptPasswordReader = func(cancel <-chan struct{}) (string, error) { return "secret-answer", nil }

	env, cleanup, err := StartPromptBroker()
	if err != nil {
		t.Fatalf("StartPromptBroker: %v", err)
	}
	defer cleanup()
	defer func() {
		localPromptLineReader = oldLineReader
		localPromptPasswordReader = oldPasswordReader
		brokerPromptLineReader = oldBrokerLineReader
		brokerPromptPasswordReader = oldBrokerPasswordReader
	}()

	for _, kv := range env {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			t.Fatalf("bad broker env: %q", kv)
		}
		t.Setenv(parts[0], parts[1])
	}

	line, err := readPromptLine()
	if err != nil {
		t.Fatalf("readPromptLine: %v", err)
	}
	if line != "line-answer" {
		t.Fatalf("unexpected line answer: %q", line)
	}

	password, err := readPromptPassword()
	if err != nil {
		t.Fatalf("readPromptPassword: %v", err)
	}
	if string(password) != "secret-answer" {
		t.Fatalf("unexpected password answer: %q", password)
	}
}

func TestPromptBrokerCleanupDoesNotWaitForAbandonedPrompt(t *testing.T) {
	oldBrokerLineReader := brokerPromptLineReader
	workerDone := make(chan struct{})
	brokerPromptLineReader = func(cancel <-chan struct{}) (string, error) {
		<-cancel
		close(workerDone)
		return "", nil
	}
	defer func() {
		<-workerDone
		brokerPromptLineReader = oldBrokerLineReader
	}()

	env, cleanup, err := StartPromptBroker()
	if err != nil {
		t.Fatalf("StartPromptBroker: %v", err)
	}

	values := map[string]string{}
	for _, kv := range env {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			t.Fatalf("bad broker env: %q", kv)
		}
		values[parts[0]] = parts[1]
	}

	conn, err := net.Dial(values[PromptBrokerNetworkEnv], values[PromptBrokerAddrEnv])
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	req := promptBrokerRequest{Token: values[PromptBrokerTokenEnv], Op: "line"}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("Encode request: %v", err)
	}
	_ = conn.Close()

	done := make(chan struct{})
	go func() {
		cleanup()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup did not return after abandoned prompt")
	}
}
