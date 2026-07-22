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
	"sync/atomic"
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
func (c *sessionConn) CloseWrite() error                  { return c.stdin.Close() }
func (c *sessionConn) Close() error                       { c.stdin.Close(); return c.session.Close() }
func (c *sessionConn) LocalAddr() net.Addr                { return nil }
func (c *sessionConn) RemoteAddr() net.Addr               { return nil }
func (c *sessionConn) SetDeadline(t time.Time) error      { return nil }
func (c *sessionConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *sessionConn) SetWriteDeadline(t time.Time) error { return nil }

type RelayPolicy string

const (
	RelayAuto    RelayPolicy = "auto"
	RelayDisable RelayPolicy = "disable"
	RelayPrefer  RelayPolicy = "prefer"
)

func normalizeRelayPolicy(policy RelayPolicy) RelayPolicy {
	switch policy {
	case RelayDisable, RelayPrefer:
		return policy
	default:
		return RelayAuto
	}
}

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
	traceSeq   atomic.Uint64
)

func newTraceID(prefix string) string {
	id := traceSeq.Add(1)
	return fmt.Sprintf("%s-%06d", prefix, id)
}

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
	return dialOrExecWithTracePolicy(client, addr, verbose, "", RelayAuto)
}

func DialTCPWithPolicy(client *ssh.Client, addr string, verbose bool, policy RelayPolicy) (net.Conn, error) {
	return dialOrExecWithTracePolicy(client, addr, verbose, "", policy)
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
	return dialOrExecWithTracePolicy(client, addr, verbose, "", RelayAuto)
}

func dialOrExecWithTrace(client *ssh.Client, addr string, verbose bool, traceID string) (net.Conn, error) {
	return dialOrExecWithTracePolicy(client, addr, verbose, traceID, RelayAuto)
}

func dialOrExecWithTracePolicy(client *ssh.Client, addr string, verbose bool, traceID string, policy RelayPolicy) (net.Conn, error) {
	policy = normalizeRelayPolicy(policy)
	if policy == RelayPrefer {
		return dialRelayThenDirect(client, addr, verbose, traceID)
	}
	if policy == RelayDisable {
		return dialDirectOnly(client, addr)
	}
	return dialDirectThenRelay(client, addr, verbose, traceID)
}

func dialDirectOnly(client *ssh.Client, addr string) (net.Conn, error) {
	conn, err := client.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return wrapIdleConn(conn, DefaultIdleTimeout), nil
}

func dialDirectThenRelay(client *ssh.Client, addr string, verbose bool, traceID string) (net.Conn, error) {
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
			if verbose && traceID != "" {
				log.Printf("[%s] direct-tcpip dial %s failed: %v", traceID, addr, err)
			}
			return nil, err
		}
		if verbose {
			if traceID != "" {
				log.Printf("[%s] direct-tcpip blocked for %s, switching to relay mode", traceID, addr)
			} else {
				log.Printf("direct-tcpip blocked for %s, switching to relay mode", addr)
			}
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
			if traceID != "" {
				log.Printf("[%s] mux dial %s failed: %v", traceID, addr, dialErr)
			} else {
				log.Printf("Mux dial %s: %v", addr, dialErr)
			}
		}
	} else if verbose {
		if traceID != "" {
			log.Printf("[%s] mux dialer init failed: %v", traceID, muxErr)
		} else {
			log.Printf("Mux dialer init: %v", muxErr)
		}
	}

	// 3) Fallback: per-connection exec relays (with semaphore + retry)
	sessionSem <- struct{}{}
	defer func() { <-sessionSem }()
	return dialExecFallback(client, cs, addr, verbose)
}

func dialRelayThenDirect(client *ssh.Client, addr string, verbose bool, traceID string) (net.Conn, error) {
	cs := getClientState(client)

	cs.mu.Lock()
	d, muxErr := getOrCreateMuxDialer(client, cs, verbose)
	cs.mu.Unlock()
	relayErr := muxErr

	if muxErr == nil {
		conn, dialErr := d.Dial(addr)
		if dialErr == nil {
			return wrapIdleConn(conn, DefaultIdleTimeout), nil
		}
		relayErr = dialErr
		if verbose {
			if traceID != "" {
				log.Printf("[%s] preferred mux dial %s failed: %v", traceID, addr, dialErr)
			} else {
				log.Printf("Preferred mux dial %s: %v", addr, dialErr)
			}
		}
	} else if verbose {
		if traceID != "" {
			log.Printf("[%s] preferred mux dialer init failed: %v", traceID, muxErr)
		} else {
			log.Printf("Preferred mux dialer init: %v", muxErr)
		}
	}

	sessionSem <- struct{}{}
	defer func() { <-sessionSem }()
	execConn, execErr := dialExecFallback(client, cs, addr, verbose)
	if execErr == nil {
		return execConn, nil
	}
	if verbose {
		if traceID != "" {
			log.Printf("[%s] preferred exec relay %s failed: %v", traceID, addr, execErr)
		} else {
			log.Printf("Preferred exec relay %s: %v", addr, execErr)
		}
	}

	conn, directErr := client.Dial("tcp", addr)
	if directErr == nil {
		return wrapIdleConn(conn, DefaultIdleTimeout), nil
	}
	return nil, fmt.Errorf("preferred relay failed for %s: mux=%v; exec=%v; direct-tcpip=%w", addr, relayErr, execErr, directErr)
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
	return StartLocalForwardWithPolicy(client, spec, verbose, RelayAuto)
}

func StartLocalForwardWithPolicy(client *ssh.Client, spec string, verbose bool, policy RelayPolicy) error {
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

	var lastFailLogUnix atomic.Int64
	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		traceID := newTraceID("L")
		if verbose {
			log.Printf("[%s] local forward accepted %s -> %s", traceID, conn.RemoteAddr(), remoteAddr)
		}
		go func(traceID string) {
			defer conn.Close()
			remote, err := dialOrExecWithTracePolicy(client, remoteAddr, verbose, traceID, policy)
			if err != nil {
				now := time.Now().UnixNano()
				prev := lastFailLogUnix.Load()
				if now-prev > int64(2*time.Second) && lastFailLogUnix.CompareAndSwap(prev, now) {
					log.Printf("[%s] local forward connect to %s failed: %v", traceID, remoteAddr, err)
				}
				return
			}
			defer remote.Close()
			if verbose {
				log.Printf("[%s] local forward connected to %s", traceID, remoteAddr)
			}
			biCopy(conn, remote)
		}(traceID)
	}
}

// StartRemoteForward starts remote port forwarding: -R [bind_address:]port:host:hostport
func StartRemoteForward(client *ssh.Client, spec string, verbose bool) error {
	return StartRemoteForwardWithPolicy(client, spec, verbose, RelayAuto)
}

func StartRemoteForwardWithPolicy(client *ssh.Client, spec string, verbose bool, policy RelayPolicy) error {
	bindAddr, localAddr, err := parseForwardSpec(spec)
	if err != nil {
		return fmt.Errorf("invalid remote forward spec %q: %w", spec, err)
	}

	policy = normalizeRelayPolicy(policy)
	if policy == RelayPrefer {
		muxListener, muxErr := listenRemoteForwardMux(client, bindAddr, verbose)
		if muxErr == nil {
			return serveRemoteForwardListener(muxListener, "Remote forward via mux relay", bindAddr, localAddr, verbose)
		}
		sshListener, sshErr := listenRemoteForwardSSH(client, bindAddr)
		if sshErr == nil {
			return serveRemoteForwardListener(sshListener, "Remote forward", bindAddr, localAddr, verbose)
		}
		return fmt.Errorf("remote forward %s: mux relay failed: %v; sshd tcpip-forward failed: %w", spec, muxErr, sshErr)
	}

	sshListener, sshErr := listenRemoteForwardSSH(client, bindAddr)
	if sshErr == nil {
		return serveRemoteForwardListener(sshListener, "Remote forward", bindAddr, localAddr, verbose)
	}
	if policy == RelayDisable || !isTCPIPForwardDenied(sshErr) {
		return fmt.Errorf("remote listen on %s: %w", bindAddr, sshErr)
	}

	muxListener, muxErr := listenRemoteForwardMux(client, bindAddr, verbose)
	if muxErr == nil {
		log.Printf("remote forward via mux relay fallback: (remote) %s -> (local) %s", bindAddr, localAddr)
		return serveRemoteForwardListener(muxListener, "Remote forward via mux relay", bindAddr, localAddr, verbose)
	}
	return fmt.Errorf("remote forward %s: sshd tcpip-forward denied: %v; mux relay failed: %w", spec, sshErr, muxErr)
}

func listenRemoteForwardSSH(client *ssh.Client, bindAddr string) (net.Listener, error) {
	listener, err := client.Listen("tcp", bindAddr)
	if err != nil {
		return nil, err
	}
	return listener, nil
}

func listenRemoteForwardMux(client *ssh.Client, bindAddr string, verbose bool) (net.Listener, error) {
	warnNonLoopbackRelayBind(bindAddr)
	cs := getClientState(client)
	cs.mu.Lock()
	d, err := getOrCreateMuxDialer(client, cs, verbose)
	cs.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return d.Listen(bindAddr)
}

func isTCPIPForwardDenied(err error) bool {
	return err != nil && strings.Contains(err.Error(), "ssh: tcpip-forward request denied by peer")
}

func warnNonLoopbackRelayBind(bindAddr string) {
	host, _, err := net.SplitHostPort(bindAddr)
	if err != nil {
		return
	}
	if host == "" {
		host = "0.0.0.0"
	}
	if strings.EqualFold(host, "localhost") {
		return
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return
	}
	log.Printf("remote relay listener is binding %s", bindAddr)
}

func serveRemoteForwardListener(listener net.Listener, label, bindAddr, localAddr string, verbose bool) error {
	defer listener.Close()

	log.Printf("%s: (remote) %s -> (local) %s", label, bindAddr, localAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("remote accept: %w", err)
		}
		traceID := newTraceID("R")
		if verbose {
			log.Printf("[%s] remote forward accepted %s -> %s", traceID, conn.RemoteAddr(), localAddr)
		}
		go func(traceID string) {
			defer conn.Close()
			local, err := net.Dial("tcp", localAddr)
			if err != nil {
				log.Printf("[%s] remote forward dial local %s failed: %v", traceID, localAddr, err)
				return
			}
			defer local.Close()
			if verbose {
				log.Printf("[%s] remote forward connected to local %s", traceID, localAddr)
			}
			biCopy(conn, local)
		}(traceID)
	}
}

// StartDynamicForward starts dynamic port forwarding (SOCKS5 server): -D [bind_address:]port
func StartDynamicForward(client *ssh.Client, spec string, verbose bool) error {
	return StartDynamicForwardWithPolicy(client, spec, verbose, RelayAuto)
}

func StartDynamicForwardWithPolicy(client *ssh.Client, spec string, verbose bool, policy RelayPolicy) error {
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
		traceID := newTraceID("D")
		go handleSocks5Client(client, conn, verbose, traceID, policy)
	}
}

func handleSocks5Client(client *ssh.Client, conn net.Conn, verbose bool, traceID string, policy RelayPolicy) {
	defer conn.Close()

	// SOCKS5 handshake
	// Read version and number-of-methods
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		if verbose {
			log.Printf("[%s] dynamic forward handshake read failed: %v", traceID, err)
		}
		return
	}
	buf := make([]byte, 258)
	copy(buf, hdr)
	if nmethods := int(hdr[1]); nmethods > 0 {
		if _, err := io.ReadFull(conn, buf[2:2+nmethods]); err != nil {
			if verbose {
				log.Printf("[%s] dynamic forward handshake methods read failed: %v", traceID, err)
			}
			return
		}
	}
	if buf[0] != 0x05 {
		if verbose {
			log.Printf("[%s] dynamic forward rejected non-socks5 client", traceID)
		}
		return
	}

	// We only support no-auth for local SOCKS5 server
	conn.Write([]byte{0x05, 0x00})

	// Read connect request header: VER CMD RSV ATYP (4 bytes)
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		if verbose {
			log.Printf("[%s] dynamic forward request read failed: %v", traceID, err)
		}
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		// Only CONNECT supported
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		if verbose {
			log.Printf("[%s] dynamic forward rejected command: ver=%d cmd=%d", traceID, buf[0], buf[1])
		}
		return
	}

	var targetHost string
	var targetPort int
	addrType := buf[3]
	var addrEnd int

	switch addrType {
	case 0x01: // IPv4: 4 addr bytes + 2 port bytes
		if _, err := io.ReadFull(conn, buf[4:10]); err != nil {
			return
		}
		targetHost = net.IP(buf[4:8]).String()
		targetPort = int(binary.BigEndian.Uint16(buf[8:10]))
		addrEnd = 10
	case 0x03: // Domain: 1 len byte + domain + 2 port bytes
		if _, err := io.ReadFull(conn, buf[4:5]); err != nil {
			return
		}
		domainLen := int(buf[4])
		domainBuf := make([]byte, domainLen+2)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return
		}
		targetHost = string(domainBuf[:domainLen])
		targetPort = int(binary.BigEndian.Uint16(domainBuf[domainLen : domainLen+2]))
		addrEnd = 5 + domainLen + 2
	case 0x04: // IPv6: 16 addr bytes + 2 port bytes
		if _, err := io.ReadFull(conn, buf[4:22]); err != nil {
			return
		}
		targetHost = net.IP(buf[4:20]).String()
		targetPort = int(binary.BigEndian.Uint16(buf[20:22]))
		addrEnd = 22
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		if verbose {
			log.Printf("[%s] dynamic forward rejected unsupported address type: %d", traceID, addrType)
		}
		return
	}
	_ = addrEnd

	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))

	if verbose {
		log.Printf("[%s] dynamic forward CONNECT %s", traceID, targetAddr)
	}

	// Dial through SSH (with exec fallback)
	remote, err := dialOrExecWithTracePolicy(client, targetAddr, verbose, traceID, policy)
	if err != nil {
		log.Printf("[%s] dynamic forward connect to %s failed: %v", traceID, targetAddr, err)
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
