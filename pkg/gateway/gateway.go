package gateway

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

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
	user, password, bindAddr, err := parseGatewaySpec(spec)
	if err != nil {
		return fmt.Errorf("gateway: %w", err)
	}

	hostKeys, err := loadOrGenerateHostKeys()
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("gateway: listen %s: %w", bindAddr, err)
	}

	if verbose {
		log.Printf("[gateway] Listening on %s (user=%s)", ln.Addr(), user)
	}
	if ready != nil {
		info, err := gatewayReadyInfo(ln, hostKeys)
		if err != nil {
			_ = ln.Close()
			return err
		}
		if err := ready(info); err != nil {
			_ = ln.Close()
			return fmt.Errorf("gateway: report ready: %w", err)
		}
	}

	return serveListener(ln, finalClient, user, password, hostKeys, verbose)
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

	// Track active downstream connections for cleanup.
	var mu sync.Mutex
	var activeConns []*ssh.ServerConn

	// Monitor upstream death.
	done := make(chan error, 1)
	go func() {
		done <- finalClient.Wait()
	}()

	// Close listener and all downstream when upstream dies.
	go func() {
		<-done
		ln.Close()
		mu.Lock()
		for _, sc := range activeConns {
			sc.Close()
		}
		mu.Unlock()
	}()

	for {
		tcpConn, err := ln.Accept()
		if err != nil {
			// Check if upstream died.
			select {
			case upErr := <-done:
				if upErr != nil {
					return fmt.Errorf("gateway: upstream died: %w", upErr)
				}
				return fmt.Errorf("gateway: upstream connection closed")
			default:
			}
			return fmt.Errorf("gateway: accept: %w", err)
		}

		go func(conn net.Conn) {
			sshConn, chans, reqs, err := ssh.NewServerConn(conn, serverConfig)
			if err != nil {
				if verbose {
					log.Printf("[gateway] handshake failed: %v", err)
				}
				conn.Close()
				return
			}

			mu.Lock()
			activeConns = append(activeConns, sshConn)
			mu.Unlock()

			// Handle global requests.
			go handleGlobalRequests(reqs, verbose)

			// Handle channels.
			handleChannels(chans, finalClient, verbose)

			// Cleanup on disconnect.
			sshConn.Close()
			mu.Lock()
			for i, sc := range activeConns {
				if sc == sshConn {
					activeConns = append(activeConns[:i], activeConns[i+1:]...)
					break
				}
			}
			mu.Unlock()
		}(tcpConn)
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
