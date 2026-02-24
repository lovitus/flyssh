package forwarding

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// sessionConn wraps an SSH exec session (running nc/socat) as a net.Conn.
type sessionConn struct {
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
}

func (c *sessionConn) Read(b []byte) (int, error)         { return c.stdout.Read(b) }
func (c *sessionConn) Write(b []byte) (int, error)        { return c.stdin.Write(b) }
func (c *sessionConn) Close() error                       { c.stdin.Close(); return c.session.Close() }
func (c *sessionConn) LocalAddr() net.Addr                { return nil }
func (c *sessionConn) RemoteAddr() net.Addr               { return nil }
func (c *sessionConn) SetDeadline(t time.Time) error      { return nil }
func (c *sessionConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *sessionConn) SetWriteDeadline(t time.Time) error { return nil }

// clientState holds per-SSH-client state for relay and mux operations.
// Each hop in a multi-hop chain gets its own clientState.
type clientState struct {
	mu               sync.Mutex
	directTCPBlocked bool
	muxDialer        *MuxDialer
	cachedRelayIdx   int // -1 = not found, -2 = embedded relay
	cachedRelayName  string
	relayPath        string
	relayUploaded    bool
	relayArch        string
}

var (
	clientStatesMu sync.Mutex
	clientStates   = make(map[*ssh.Client]*clientState)

	// sessionSem limits concurrent SSH exec sessions to stay under MaxSessions.
	sessionSem = make(chan struct{}, 8)
)

func getClientState(client *ssh.Client) *clientState {
	clientStatesMu.Lock()
	defer clientStatesMu.Unlock()
	s, ok := clientStates[client]
	if !ok {
		s = &clientState{cachedRelayIdx: -1}
		clientStates[client] = s
	}
	return s
}

// CleanupClient removes per-client state when a client is closed.
func CleanupClient(client *ssh.Client) {
	clientStatesMu.Lock()
	cs, ok := clientStates[client]
	delete(clientStates, client)
	clientStatesMu.Unlock()
	if ok && cs.muxDialer != nil {
		cs.muxDialer.Close()
	}
}

type relayCmd struct {
	name string
	cmd  string
}

func buildRelayCmds(host, port string) []relayCmd {
	pyRelay := fmt.Sprintf(
		"import socket,os,sys,threading;"+
			"s=socket.socket();"+
			"s.connect(('%s',%s));"+
			"threading.Thread(target=lambda:[s.sendall(d) for d in iter(lambda:os.read(0,65536),b'')],daemon=True).start();"+
			"[os.write(1,d) for d in iter(lambda:s.recv(65536),b'')]",
		host, port,
	)

	perlRelay := fmt.Sprintf(
		"use IO::Socket::INET;use IO::Select;"+
			"my $s=IO::Socket::INET->new(PeerAddr=>'%s',PeerPort=>%s,Proto=>'tcp') or die;"+
			"my $sel=IO::Select->new($s,\\*STDIN);"+
			"while(my @r=$sel->can_read){"+
			"for(@r){if($_==$s){sysread($s,my $b,65536)||exit;syswrite(STDOUT,$b)}"+
			"else{sysread(STDIN,my $b,65536)||exit;syswrite($s,$b)}}}",
		host, port,
	)

	return []relayCmd{
		{"nc", fmt.Sprintf("nc %s %s", host, port)},
		{"socat", fmt.Sprintf("socat - TCP:%s:%s", host, port)},
		{"perl", fmt.Sprintf("perl -e '%s'", perlRelay)},
		{"python3", fmt.Sprintf("python3 -c \"%s\"", pyRelay)},
		{"python", fmt.Sprintf("python -c \"%s\"", pyRelay)},
		{"bash", fmt.Sprintf("bash -c 'exec 3<>/dev/tcp/%s/%s; cat <&3 & cat >&3; wait'", host, port)},
	}
}

// DialTCP opens a TCP connection through the SSH client to addr (host:port).
// Tries direct-tcpip → mux relay → per-session exec relays.
// Safe for concurrent use from any goroutine and any hop.
func DialTCP(client *ssh.Client, addr string, verbose bool) (net.Conn, error) {
	return dialOrExec(client, addr, verbose)
}

// getOrCreateMuxDialer returns the per-client MuxDialer, creating it if needed.
func getOrCreateMuxDialer(client *ssh.Client, cs *clientState, verbose bool) (*MuxDialer, error) {
	if cs.muxDialer != nil && !cs.muxDialer.IsClosed() {
		return cs.muxDialer, nil
	}

	relayPath, err := getOrUploadRelay(client, cs, verbose)
	if err != nil {
		return nil, err
	}

	d, err := NewMuxDialer(client, relayPath, verbose)
	if err != nil {
		return nil, err
	}
	cs.muxDialer = d
	return d, nil
}

// dialOrExec tries direct-tcpip → mux relay → per-session exec relays.
// All state is per-client so each hop in a chain is independent.
func dialOrExec(client *ssh.Client, addr string, verbose bool) (net.Conn, error) {
	cs := getClientState(client)

	// 1) Try direct-tcpip (fastest, standard SSH forwarding)
	cs.mu.Lock()
	blocked := cs.directTCPBlocked
	cs.mu.Unlock()

	if !blocked {
		conn, err := client.Dial("tcp", addr)
		if err == nil {
			return wrapIdleConn(conn, DefaultIdleTimeout), nil
		}
		if !strings.Contains(err.Error(), "administratively prohibited") {
			return nil, err
		}
		cs.mu.Lock()
		cs.directTCPBlocked = true
		cs.mu.Unlock()
	}

	// 2) Try mux relay (1 SSH session, unlimited connections)
	cs.mu.Lock()
	d, muxErr := getOrCreateMuxDialer(client, cs, verbose)
	cs.mu.Unlock()

	if muxErr == nil {
		conn, dialErr := d.Dial(addr)
		if dialErr == nil {
			return wrapIdleConn(conn, DefaultIdleTimeout), nil
		}
		if verbose {
			log.Printf("Mux dial %s: %v", addr, dialErr)
		}
	} else if verbose {
		log.Printf("Mux dialer init: %v", muxErr)
	}

	// 3) Fallback: per-connection exec relays (with semaphore + retry)
	sessionSem <- struct{}{}
	defer func() { <-sessionSem }()
	return dialExecFallback(client, cs, addr, verbose)
}

// dialExecFallback tries per-connection exec relays with retry on "open failed".
func dialExecFallback(client *ssh.Client, cs *clientState, addr string, verbose bool) (net.Conn, error) {
	const maxRetries = 5
	const retryDelay = 200 * time.Millisecond

	for attempt := 0; attempt <= maxRetries; attempt++ {
		sc, err := dialExecOnce(client, cs, addr, verbose && attempt == 0)
		if err == nil {
			return wrapIdleConn(sc, DefaultIdleTimeout), nil
		}
		if !strings.Contains(err.Error(), "open failed") {
			return nil, err
		}
		if attempt < maxRetries {
			time.Sleep(retryDelay * time.Duration(attempt+1))
		}
	}
	return nil, fmt.Errorf("exec relay: max retries exhausted (server session limit)")
}

// dialExecOnce tries all single-session relay methods once.
func dialExecOnce(client *ssh.Client, cs *clientState, addr string, verbose bool) (net.Conn, error) {
	host, port, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return nil, fmt.Errorf("bad addr %q: %w", addr, splitErr)
	}

	idx := cs.cachedRelayIdx

	if idx == -2 {
		relayPath, err := getOrUploadRelay(client, cs, verbose)
		if err == nil {
			sc, err := tryExecRelay(client, fmt.Sprintf("%s %s", relayPath, addr))
			if err == nil {
				return sc, nil
			}
		}
		cs.cachedRelayIdx = -1
	} else if idx >= 0 {
		cmds := buildRelayCmds(host, port)
		if idx < len(cmds) {
			sc, err := tryExecRelay(client, cmds[idx].cmd)
			if err == nil {
				return sc, nil
			}
		}
		cs.cachedRelayIdx = -1
	}

	// Full discovery: try embedded relay (single-session), nc, socat, perl, python, bash
	relayPath, relayErr := getOrUploadRelay(client, cs, verbose)
	if relayErr == nil {
		sc, err := tryExecRelay(client, fmt.Sprintf("%s %s", relayPath, addr))
		if err == nil {
			if cs.cachedRelayIdx == -1 {
				cs.cachedRelayIdx = -2
				cs.cachedRelayName = "embedded-relay"
				log.Printf("Forwarding: direct-tcpip blocked, using embedded relay for %s", addr)
			}
			return sc, nil
		}
		if verbose {
			log.Printf("Single-session relay failed: %v", err)
		}
	}

	cmds := buildRelayCmds(host, port)
	var lastErr error
	var triedNames []string
	for i, c := range cmds {
		sc, err := tryExecRelay(client, c.cmd)
		if err != nil {
			triedNames = append(triedNames, c.name)
			lastErr = err
			if verbose {
				log.Printf("Exec relay %s: %v", c.name, err)
			}
			continue
		}
		if cs.cachedRelayIdx == -1 {
			cs.cachedRelayIdx = i
			cs.cachedRelayName = c.name
			log.Printf("Forwarding: direct-tcpip blocked, using %s relay for %s", c.name, addr)
		}
		return sc, nil
	}

	return nil, fmt.Errorf("all relay methods failed: mux+embedded+[%s]: %v",
		strings.Join(triedNames, ","), lastErr)
}

// tryExecRelay starts a relay command and verifies it stays alive briefly.
func tryExecRelay(client *ssh.Client, cmd string) (*sessionConn, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}

	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()

	var stderrBuf bytes.Buffer
	sess.Stderr = &stderrBuf

	if err := sess.Start(cmd); err != nil {
		sess.Close()
		return nil, fmt.Errorf("start: %w", err)
	}

	// Wait briefly to detect immediate failures (command not found, connect refused)
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()

	select {
	case exitErr := <-done:
		stderr := strings.TrimSpace(stderrBuf.String())
		sess.Close()
		if stderr != "" {
			return nil, fmt.Errorf("%s", stderr)
		}
		if exitErr != nil {
			return nil, fmt.Errorf("exited: %v", exitErr)
		}
		return nil, fmt.Errorf("exited immediately")
	case <-time.After(300 * time.Millisecond):
		// Still running — relay is connected
	}

	return &sessionConn{session: sess, stdin: stdin, stdout: stdout}, nil
}

// StartLocalForward starts local port forwarding: -L [bind_address:]port:host:hostport
func StartLocalForward(client *ssh.Client, spec string, verbose bool) error {
	bindAddr, remoteAddr, err := parseForwardSpec(spec)
	if err != nil {
		return fmt.Errorf("invalid local forward spec %q: %w", spec, err)
	}

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", bindAddr, err)
	}
	defer listener.Close()

	// Close listener when SSH connection dies so accept loop exits
	go func() { client.Wait(); listener.Close() }()

	log.Printf("Local forward: %s -> (remote) %s", listener.Addr(), remoteAddr)

	var lastLogTime time.Time
	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go func() {
			defer conn.Close()
			remote, err := dialOrExec(client, remoteAddr, verbose)
			if err != nil {
				now := time.Now()
				if now.Sub(lastLogTime) > 2*time.Second {
					log.Printf("Local forward: connect to %s failed: %v", remoteAddr, err)
					lastLogTime = now
				}
				return
			}
			defer remote.Close()
			biCopy(conn, remote)
		}()
	}
}

// StartRemoteForward starts remote port forwarding: -R [bind_address:]port:host:hostport
func StartRemoteForward(client *ssh.Client, spec string, verbose bool) error {
	bindAddr, localAddr, err := parseForwardSpec(spec)
	if err != nil {
		return fmt.Errorf("invalid remote forward spec %q: %w", spec, err)
	}

	listener, err := client.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("remote listen on %s: %w", bindAddr, err)
	}
	defer listener.Close()

	log.Printf("Remote forward: (remote) %s -> (local) %s", bindAddr, localAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("remote accept: %w", err)
		}
		go func() {
			defer conn.Close()
			local, err := net.Dial("tcp", localAddr)
			if err != nil {
				log.Printf("Remote forward: dial local %s failed: %v", localAddr, err)
				return
			}
			defer local.Close()
			biCopy(conn, local)
		}()
	}
}

// StartDynamicForward starts dynamic port forwarding (SOCKS5 server): -D [bind_address:]port
func StartDynamicForward(client *ssh.Client, spec string, verbose bool) error {
	bindAddr := spec
	if !strings.Contains(bindAddr, ":") {
		bindAddr = "127.0.0.1:" + bindAddr
	}

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("dynamic forward listen on %s: %w", bindAddr, err)
	}
	defer listener.Close()

	// Close listener when SSH connection dies
	go func() { client.Wait(); listener.Close() }()

	log.Printf("Dynamic forward (SOCKS5): listening on %s", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("dynamic accept: %w", err)
		}
		go handleSocks5Client(client, conn, verbose)
	}
}

func handleSocks5Client(client *ssh.Client, conn net.Conn, verbose bool) {
	defer conn.Close()

	// SOCKS5 handshake
	// Read version and auth methods
	buf := make([]byte, 258)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return
	}
	if buf[0] != 0x05 {
		return
	}

	// We only support no-auth for local SOCKS5 server
	conn.Write([]byte{0x05, 0x00})

	// Read connect request
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		// Only CONNECT supported
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetHost string
	var targetPort int
	addrType := buf[3]
	var addrEnd int

	switch addrType {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		targetHost = net.IP(buf[4:8]).String()
		targetPort = int(binary.BigEndian.Uint16(buf[8:10]))
		addrEnd = 10
	case 0x03: // Domain
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		targetHost = string(buf[5 : 5+domainLen])
		targetPort = int(binary.BigEndian.Uint16(buf[5+domainLen : 5+domainLen+2]))
		addrEnd = 5 + domainLen + 2
	case 0x04: // IPv6
		if n < 22 {
			return
		}
		targetHost = net.IP(buf[4:20]).String()
		targetPort = int(binary.BigEndian.Uint16(buf[20:22]))
		addrEnd = 22
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	_ = addrEnd

	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))

	if verbose {
		log.Printf("Dynamic forward: CONNECT %s", targetAddr)
	}

	// Dial through SSH (with exec fallback)
	remote, err := dialOrExec(client, targetAddr, verbose)
	if err != nil {
		log.Printf("Dynamic forward: connect to %s failed: %v", targetAddr, err)
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	// Success reply
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(reply)

	// Bidirectional copy
	biCopy(conn, remote)
}

func biCopy(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		if tc, ok := b.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		if tc, ok := a.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	wg.Wait()
}

// parseForwardSpec parses "[bind_address:]port:host:hostport" into bind and remote addresses
func parseForwardSpec(spec string) (bindAddr, remoteAddr string, err error) {
	parts := strings.Split(spec, ":")
	switch len(parts) {
	case 3:
		// port:host:hostport
		bindAddr = "127.0.0.1:" + parts[0]
		remoteAddr = net.JoinHostPort(parts[1], parts[2])
	case 4:
		// bind_address:port:host:hostport
		bindAddr = net.JoinHostPort(parts[0], parts[1])
		remoteAddr = net.JoinHostPort(parts[2], parts[3])
	default:
		err = fmt.Errorf("expected [bind_address:]port:host:hostport, got %q", spec)
	}
	return
}
