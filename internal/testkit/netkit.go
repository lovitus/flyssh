package testkit

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHServer struct {
	Addr string

	listener net.Listener
	config   *ssh.ServerConfig

	closeOnce sync.Once
}

func StartSSHServer(t *testing.T, users map[string]string) *SSHServer {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test host key: %v", err)
	}
	privateKey, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatalf("build host signer: %v", err)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			expect, ok := users[c.User()]
			if !ok || expect != string(pass) {
				return nil, fmt.Errorf("bad credentials")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(privateKey)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ssh server: %v", err)
	}

	s := &SSHServer{
		Addr:     ln.Addr().String(),
		listener: ln,
		config:   cfg,
	}

	go s.acceptLoop()
	t.Cleanup(s.Close)
	return s
}

func (s *SSHServer) Close() {
	s.closeOnce.Do(func() {
		_ = s.listener.Close()
	})
}

func (s *SSHServer) acceptLoop() {
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(c)
	}
}

func (s *SSHServer) handleConn(raw net.Conn) {
	defer raw.Close()

	serverConn, chans, reqs, err := ssh.NewServerConn(raw, s.config)
	if err != nil {
		return
	}
	defer serverConn.Close()

	fw := newRemoteForwardManager(serverConn)
	defer fw.Close()

	go fw.handleGlobalRequests(reqs)

	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "direct-tcpip":
			s.handleDirectTCPIP(newChannel)
		case "session":
			s.handleSession(newChannel)
		default:
			_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
}

func (s *SSHServer) handleDirectTCPIP(newChannel ssh.NewChannel) {
	var p struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(newChannel.ExtraData(), &p); err != nil {
		_ = newChannel.Reject(ssh.Prohibited, "bad direct-tcpip payload")
		return
	}

	target, err := net.DialTimeout("tcp", net.JoinHostPort(p.DestAddr, strconv.Itoa(int(p.DestPort))), 5*time.Second)
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newChannel.Accept()
	if err != nil {
		_ = target.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go relayConns(ch, target)
}

func (s *SSHServer) handleSession(newChannel ssh.NewChannel) {
	ch, reqs, err := newChannel.Accept()
	if err != nil {
		return
	}

	go func() {
		defer ch.Close()
		for req := range reqs {
			switch req.Type {
			case "pty-req", "env":
				_ = req.Reply(true, nil)
			case "exec":
				_ = req.Reply(true, nil)
				cmd := parseExecRequest(req.Payload)
				status := runExecCommand(cmd, ch)
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: status}))
				return
			case "shell":
				_ = req.Reply(false, nil)
				return
			default:
				_ = req.Reply(false, nil)
			}
		}
	}()
}

func runExecCommand(command string, out io.Writer) uint32 {
	if command == "" {
		return 0
	}
	cmd := exec.Command("sh", "-lc", command)
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return uint32(ee.ExitCode())
		}
		return 1
	}
	return 0
}

func parseExecRequest(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	n := int(binary.BigEndian.Uint32(payload[:4]))
	if 4+n > len(payload) || n < 0 {
		return ""
	}
	return string(payload[4 : 4+n])
}

type remoteForwardManager struct {
	conn *ssh.ServerConn

	mu        sync.Mutex
	listeners map[string]net.Listener
}

func newRemoteForwardManager(conn *ssh.ServerConn) *remoteForwardManager {
	return &remoteForwardManager{
		conn:      conn,
		listeners: make(map[string]net.Listener),
	}
}

func (m *remoteForwardManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ln := range m.listeners {
		_ = ln.Close()
	}
	m.listeners = make(map[string]net.Listener)
}

func (m *remoteForwardManager) handleGlobalRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			m.handleTCPIPForward(req)
		case "cancel-tcpip-forward":
			m.handleCancelTCPIPForward(req)
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (m *remoteForwardManager) handleTCPIPForward(req *ssh.Request) {
	var p struct {
		Addr string
		Port uint32
	}
	if err := ssh.Unmarshal(req.Payload, &p); err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	bindAddr := p.Addr
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(bindAddr, strconv.Itoa(int(p.Port))))
	if err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	actualPort := uint32(ln.Addr().(*net.TCPAddr).Port)
	key := net.JoinHostPort(bindAddr, strconv.Itoa(int(actualPort)))

	m.mu.Lock()
	m.listeners[key] = ln
	m.mu.Unlock()

	if req.WantReply {
		out := make([]byte, 4)
		binary.BigEndian.PutUint32(out, actualPort)
		_ = req.Reply(true, out)
	}

	go m.acceptForwarded(ln)
}

func (m *remoteForwardManager) handleCancelTCPIPForward(req *ssh.Request) {
	var p struct {
		Addr string
		Port uint32
	}
	if err := ssh.Unmarshal(req.Payload, &p); err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	key := net.JoinHostPort(p.Addr, strconv.Itoa(int(p.Port)))
	m.mu.Lock()
	ln, ok := m.listeners[key]
	if ok {
		delete(m.listeners, key)
	}
	m.mu.Unlock()

	if ok {
		_ = ln.Close()
	}
	if req.WantReply {
		_ = req.Reply(true, nil)
	}
}

func (m *remoteForwardManager) acceptForwarded(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			raddr, _ := c.RemoteAddr().(*net.TCPAddr)
			laddr, _ := c.LocalAddr().(*net.TCPAddr)
			payload := struct {
				ConnectedAddr  string
				ConnectedPort  uint32
				OriginatorAddr string
				OriginatorPort uint32
			}{
				ConnectedAddr:  laddr.IP.String(),
				ConnectedPort:  uint32(laddr.Port),
				OriginatorAddr: raddr.IP.String(),
				OriginatorPort: uint32(raddr.Port),
			}

			ch, reqs, err := m.conn.OpenChannel("forwarded-tcpip", ssh.Marshal(&payload))
			if err != nil {
				return
			}
			go ssh.DiscardRequests(reqs)
			relayConns(ch, c)
		}(conn)
	}
}

type SOCKS5Proxy struct {
	Addr string

	listener  net.Listener
	username  string
	password  string
	closeOnce sync.Once
}

func StartSOCKS5Proxy(t *testing.T, username, password string) *SOCKS5Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks proxy: %v", err)
	}
	p := &SOCKS5Proxy{
		Addr:     ln.Addr().String(),
		listener: ln,
		username: username,
		password: password,
	}
	go p.acceptLoop()
	t.Cleanup(p.Close)
	return p
}

func (p *SOCKS5Proxy) Close() {
	p.closeOnce.Do(func() { _ = p.listener.Close() })
}

func (p *SOCKS5Proxy) acceptLoop() {
	for {
		c, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handleConn(c)
	}
}

func (p *SOCKS5Proxy) handleConn(c net.Conn) {
	defer c.Close()

	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	if head[0] != 0x05 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}

	wantAuth := p.username != ""
	chosen := byte(0x00)
	if wantAuth {
		chosen = 0x02
	}

	hasChosen := false
	for _, m := range methods {
		if m == chosen {
			hasChosen = true
			break
		}
	}
	if !hasChosen {
		_, _ = c.Write([]byte{0x05, 0xFF})
		return
	}
	_, _ = c.Write([]byte{0x05, chosen})

	if chosen == 0x02 {
		if !p.handleUserPassAuth(c) {
			return
		}
	}

	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(c, reqHead); err != nil {
		return
	}
	if reqHead[0] != 0x05 || reqHead[1] != 0x01 {
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	host, port, ok := readSOCKSAddress(c, reqHead[3])
	if !ok {
		return
	}
	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()

	_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	relayConns(c, target)
}

func (p *SOCKS5Proxy) handleUserPassAuth(c net.Conn) bool {
	h := make([]byte, 2)
	if _, err := io.ReadFull(c, h); err != nil {
		return false
	}
	if h[0] != 0x01 {
		_, _ = c.Write([]byte{0x01, 0x01})
		return false
	}
	ulen := int(h[1])
	u := make([]byte, ulen)
	if _, err := io.ReadFull(c, u); err != nil {
		return false
	}
	var plen [1]byte
	if _, err := io.ReadFull(c, plen[:]); err != nil {
		return false
	}
	pwd := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(c, pwd); err != nil {
		return false
	}

	if string(u) != p.username || string(pwd) != p.password {
		_, _ = c.Write([]byte{0x01, 0x01})
		return false
	}
	_, _ = c.Write([]byte{0x01, 0x00})
	return true
}

func readSOCKSAddress(r io.Reader, atyp byte) (string, int, bool) {
	switch atyp {
	case 0x01:
		var raw [4]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return "", 0, false
		}
		var p [2]byte
		if _, err := io.ReadFull(r, p[:]); err != nil {
			return "", 0, false
		}
		return net.IP(raw[:]).String(), int(binary.BigEndian.Uint16(p[:])), true
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", 0, false
		}
		d := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, d); err != nil {
			return "", 0, false
		}
		var p [2]byte
		if _, err := io.ReadFull(r, p[:]); err != nil {
			return "", 0, false
		}
		return string(d), int(binary.BigEndian.Uint16(p[:])), true
	case 0x04:
		var raw [16]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return "", 0, false
		}
		var p [2]byte
		if _, err := io.ReadFull(r, p[:]); err != nil {
			return "", 0, false
		}
		return net.IP(raw[:]).String(), int(binary.BigEndian.Uint16(p[:])), true
	default:
		return "", 0, false
	}
}

func StartTCPEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo server: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func WaitForTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", addr)
}

func relayConns(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
	}()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}
