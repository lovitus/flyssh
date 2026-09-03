package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flyssh/flyssh/internal/testkit"
	"github.com/flyssh/flyssh/pkg/cli"
	"github.com/flyssh/flyssh/pkg/config"
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

func TestPasswordCacheIsScopedByResolvedEndpoint(t *testing.T) {
	cache := NewPasswordCache()
	first := &config.ResolvedConfig{User: "alice", Hostname: "host.example", Port: 22}
	second := &config.ResolvedConfig{User: "bob", Hostname: "host.example", Port: 22}
	third := &config.ResolvedConfig{User: "alice", Hostname: "host.example", Port: 2222}

	cache.Store(first, "first-password")
	if got, ok := cache.Get(first); !ok || got != "first-password" {
		t.Fatalf("first cache = %q, %v", got, ok)
	}
	if _, ok := cache.Get(second); ok {
		t.Fatal("password leaked across users")
	}
	if _, ok := cache.Get(third); ok {
		t.Fatal("password leaked across ports")
	}
	if !cache.Forget(first) {
		t.Fatal("expected cached password to be forgotten")
	}
	if _, ok := cache.Get(first); ok {
		t.Fatal("forgotten password remained cached")
	}
}

func TestBuildAuthMethodsCachesPromptedPassword(t *testing.T) {
	server := testkit.StartSSHServer(t, map[string]string{"user": "prompted-password"})
	host, portText, err := net.SplitHostPort(server.Addr)
	if err != nil {
		t.Fatalf("split test SSH server address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse test SSH server port: %v", err)
	}

	oldReader := localPromptPasswordReader
	defer func() { localPromptPasswordReader = oldReader }()
	reads := 0
	localPromptPasswordReader = func() ([]byte, error) {
		reads++
		return []byte("prompted-password"), nil
	}

	cache := NewPasswordCache()
	cfg := &config.ResolvedConfig{User: "user", Hostname: host, Port: port, ConnectTimeout: time.Second}
	opts := &cli.Options{}
	first := dialWithCachedAuth(t, cfg, opts, cache)
	_ = first.Close()
	if reads != 1 {
		t.Fatalf("first connection prompt reads = %d, want 1", reads)
	}
	if password, ok := cache.Get(cfg); !ok || password != "prompted-password" {
		t.Fatalf("cached password = %q, %v", password, ok)
	}

	localPromptPasswordReader = func() ([]byte, error) {
		t.Fatal("second connection unexpectedly prompted for password")
		return nil, nil
	}
	second := dialWithCachedAuth(t, cfg, opts, cache)
	_ = second.Close()
}

func TestCachedPasswordIsRemovedAfterAuthenticationFailure(t *testing.T) {
	server := testkit.StartSSHServer(t, map[string]string{"user": "correct-password"})
	host, portText, err := net.SplitHostPort(server.Addr)
	if err != nil {
		t.Fatalf("split test SSH server address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse test SSH server port: %v", err)
	}

	cache := NewPasswordCache()
	cfg := &config.ResolvedConfig{User: "user", Hostname: host, Port: port, ConnectTimeout: time.Second}
	cache.Store(cfg, "stale-password")
	methods, err := BuildAuthMethodsWithPasswordCache(cfg, &cli.Options{}, cache)
	if err != nil {
		t.Fatalf("build auth methods: %v", err)
	}
	clientConfig := &ssh.ClientConfig{User: cfg.User, Auth: methods, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: cfg.ConnectTimeout}
	conn, err := net.DialTimeout("tcp", server.Addr, time.Second)
	if err != nil {
		t.Fatalf("dial test SSH server: %v", err)
	}
	_, _, _, err = ssh.NewClientConn(conn, server.Addr, clientConfig)
	_ = conn.Close()
	if !IsAuthenticationFailure(err) {
		t.Fatalf("handshake error = %v, want authentication failure", err)
	}
	cache.Forget(cfg)
	if _, ok := cache.Get(cfg); ok {
		t.Fatal("stale password remained cached after authentication failure")
	}
}

func dialWithCachedAuth(t *testing.T, cfg *config.ResolvedConfig, opts *cli.Options, cache *PasswordCache) *ssh.Client {
	t.Helper()
	methods, err := BuildAuthMethodsWithPasswordCache(cfg, opts, cache)
	if err != nil {
		t.Fatalf("build auth methods: %v", err)
	}
	clientConfig := &ssh.ClientConfig{User: cfg.User, Auth: methods, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: cfg.ConnectTimeout}
	address := net.JoinHostPort(cfg.Hostname, strconv.Itoa(cfg.Port))
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("dial test SSH server: %v", err)
	}
	sshConn, channels, requests, err := ssh.NewClientConn(conn, address, clientConfig)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("SSH handshake: %v", err)
	}
	return ssh.NewClient(sshConn, channels, requests)
}

func TestIsAuthenticationFailure(t *testing.T) {
	if !IsAuthenticationFailure(errors.New("ssh: unable to authenticate, attempted methods [none password]")) {
		t.Fatal("expected SSH authentication failure")
	}
	if IsAuthenticationFailure(errors.New("read tcp: connection reset by peer")) {
		t.Fatal("network failure must not invalidate cached password")
	}
}

func TestPromptBrokerCleanupDoesNotWaitForAbandonedPrompt(t *testing.T) {
	oldListenerFactory := promptBrokerListenerFactory
	oldBrokerLineReader := brokerPromptLineReader
	workerStarted := make(chan struct{})
	workerDone := make(chan struct{})
	serverConn, clientConn := net.Pipe()
	promptBrokerListenerFactory = func() (string, net.Listener, func(), error) {
		return "pipe", &singleConnListener{
			connCh:  chanWithConn(serverConn),
			closeCh: make(chan struct{}),
			addr:    dummyAddr("prompt-broker-test"),
		}, func() {}, nil
	}
	brokerPromptLineReader = func(cancel <-chan struct{}) (string, error) {
		close(workerStarted)
		<-cancel
		close(workerDone)
		return "", nil
	}
	defer func() {
		_ = clientConn.Close()
		promptBrokerListenerFactory = oldListenerFactory
		select {
		case <-workerDone:
		case <-time.After(2 * time.Second):
			t.Fatal("prompt worker did not exit")
		}
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

	req := promptBrokerRequest{Token: values[PromptBrokerTokenEnv], Op: "line"}
	if err := json.NewEncoder(clientConn).Encode(req); err != nil {
		t.Fatalf("Encode request: %v", err)
	}

	select {
	case <-workerStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("prompt worker did not start")
	}
	_ = clientConn.Close()

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

func chanWithConn(conn net.Conn) chan net.Conn {
	ch := make(chan net.Conn, 1)
	ch <- conn
	return ch
}

type singleConnListener struct {
	connCh  chan net.Conn
	closeCh chan struct{}
	addr    net.Addr
	once    sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connCh:
		if conn == nil {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-l.closeCh:
		return nil, net.ErrClosed
	}
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() {
		close(l.closeCh)
		close(l.connCh)
	})
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.addr
}

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }

func (a dummyAddr) String() string { return string(a) }
