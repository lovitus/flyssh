package gateway

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ReadyInfo describes a gateway listener after it is ready to accept clients.
// HostKeys contains SHA256 fingerprints suitable for client-side pinning.
type ReadyInfo struct {
	Address  string   `json:"address"`
	Port     int      `json:"port"`
	HostKeys []string `json:"host_keys"`
}

// Serve starts a local SSH gateway server that proxies connections to the
// upstream finalClient. It blocks until the upstream connection dies or the
// listener is closed. spec format: "user:pass@bind:port".
func Serve(finalClient *ssh.Client, spec string, verbose bool) error {
	return ServeWithReady(finalClient, spec, verbose, nil)
}

// ServeWithReady is Serve with an optional callback invoked after the local
// listener is ready and before the accept loop starts.
func ServeWithReady(finalClient *ssh.Client, spec string, verbose bool, ready func(ReadyInfo) error) error {
	server, err := Listen(spec, verbose)
	if err != nil {
		return err
	}
	defer server.Close()
	if ready != nil {
		if err := ready(server.Info()); err != nil {
			return fmt.Errorf("gateway: report ready: %w", err)
		}
	}
	return server.Serve(finalClient)
}

// Listen reserves the gateway endpoint until Close, independently of upstream
// connections. Serve can be called sequentially with replacement SSH clients.
func Listen(spec string, verbose bool) (*Server, error) {
	user, password, bindAddr, err := parseGatewaySpec(spec)
	if err != nil {
		return nil, fmt.Errorf("gateway: %w", err)
	}

	hostKeys, err := loadOrGenerateHostKeys()
	if err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("gateway: listen %s: %w", bindAddr, err)
	}

	if verbose {
		log.Printf("[gateway] Listening on %s (user=%s)", ln.Addr(), user)
	}
	info, err := gatewayReadyInfo(ln, hostKeys)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	server := newServer(ln, user, password, hostKeys, verbose)
	server.info = info
	return server, nil
}

func gatewayReadyInfo(ln net.Listener, hostKeys []ssh.Signer) (ReadyInfo, error) {
	address := ln.Addr().String()
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return ReadyInfo{}, fmt.Errorf("gateway: parse listener address %q: %w", address, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return ReadyInfo{}, fmt.Errorf("gateway: invalid listener port %q", portText)
	}
	fingerprints := make([]string, 0, len(hostKeys))
	for _, signer := range hostKeys {
		fingerprints = append(fingerprints, ssh.FingerprintSHA256(signer.PublicKey()))
	}
	return ReadyInfo{Address: address, Port: port, HostKeys: fingerprints}, nil
}

// serveListener is the internal serve loop, separated for testability.
func serveListener(ln net.Listener, finalClient *ssh.Client, user, password string, hostKeys []ssh.Signer, verbose bool) error {
	server := newServer(ln, user, password, hostKeys, verbose)
	defer server.Close()
	return server.Serve(finalClient)
}

type Server struct {
	listener net.Listener
	config   *ssh.ServerConfig
	info     ReadyInfo
	verbose  bool
	accepted chan net.Conn
	closed   chan struct{}
	once     sync.Once
}

func newServer(ln net.Listener, user, password string, hostKeys []ssh.Signer, verbose bool) *Server {
	expectedUser := []byte(user)
	expectedPassword := []byte(password)
	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			userOK := subtle.ConstantTimeCompare([]byte(conn.User()), expectedUser) == 1
			passOK := subtle.ConstantTimeCompare(pass, expectedPassword) == 1
			if userOK && passOK {
				return nil, nil
			}
			return nil, fmt.Errorf("authentication failed")
		},
	}
	for _, hk := range hostKeys {
		serverConfig.AddHostKey(hk)
	}

	s := &Server{listener: ln, config: serverConfig, verbose: verbose,
		accepted: make(chan net.Conn), closed: make(chan struct{})}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				s.Close()
				return
			}
			select {
			case s.accepted <- conn:
			case <-s.closed:
				_ = conn.Close()
				return
			}
		}
	}()
	return s
}

func (s *Server) Info() ReadyInfo { return s.info }

func (s *Server) Close() error {
	s.once.Do(func() {
		close(s.closed)
		_ = s.listener.Close()
	})
	return nil
}

// Serve ends all downstream connections belonging to this upstream generation,
// including connections still authenticating. It never releases the listener.
func (s *Server) Serve(upstream *ssh.Client) error {
	var mu sync.Mutex
	active := make(map[net.Conn]struct{})
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for conn := range active {
			_ = conn.Close()
		}
	}()
	done := make(chan error, 1)
	go func() { done <- upstream.Wait() }()
	for {
		select {
		case <-s.closed:
			return fmt.Errorf("gateway: listener closed: %w", net.ErrClosed)
		case err := <-done:
			if err != nil {
				return fmt.Errorf("gateway: upstream connection lost: %w", err)
			}
			return fmt.Errorf("gateway: upstream connection closed")
		case conn := <-s.accepted:
			mu.Lock()
			active[conn] = struct{}{}
			mu.Unlock()
			go func() {
				defer func() {
					_ = conn.Close()
					mu.Lock()
					delete(active, conn)
					mu.Unlock()
				}()
				_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
				sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
				if err != nil {
					if s.verbose {
						log.Printf("[gateway] handshake failed: %v", err)
					}
					return
				}
				defer sshConn.Close()
				_ = conn.SetDeadline(time.Time{})
				go handleGlobalRequests(reqs, s.verbose)
				handleChannels(chans, upstream, s.verbose)
			}()
		}
	}
}

// handleGlobalRequests responds to global requests from downstream clients.
func handleGlobalRequests(reqs <-chan *ssh.Request, verbose bool) {
	for req := range reqs {
		if req == nil {
			return
		}
		switch req.Type {
		case "keepalive@openssh.com":
			if req.WantReply {
				req.Reply(true, nil)
			}
		default:
			if verbose {
				log.Printf("[gateway] rejected global request: %s", req.Type)
			}
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// parseGatewaySpec parses "user:pass@bind:port" into components.
// v1 intentionally keeps this parser simple; gateway passwords containing
// escaped ':' or '@' are not supported yet.
func parseGatewaySpec(spec string) (user, password, bindAddr string, err error) {
	atIdx := strings.LastIndex(spec, "@")
	if atIdx < 0 {
		return "", "", "", fmt.Errorf("expected user:pass@bind:port, got %q", spec)
	}

	userPass := spec[:atIdx]
	bindAddr = spec[atIdx+1:]

	colonIdx := strings.Index(userPass, ":")
	if colonIdx < 0 {
		return "", "", "", fmt.Errorf("expected user:pass in %q", spec)
	}

	user = userPass[:colonIdx]
	password = userPass[colonIdx+1:]

	if user == "" {
		return "", "", "", fmt.Errorf("empty user in gateway spec %q", spec)
	}
	if password == "" {
		return "", "", "", fmt.Errorf("empty password in gateway spec %q", spec)
	}
	if bindAddr == "" {
		return "", "", "", fmt.Errorf("empty bind address in gateway spec %q", spec)
	}

	// Ensure bind address has host:port format.
	if _, _, err := net.SplitHostPort(bindAddr); err != nil {
		return "", "", "", fmt.Errorf("invalid bind address %q: %w", bindAddr, err)
	}

	return user, password, bindAddr, nil
}
