//go:build linux || darwin || freebsd

package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	mosh "github.com/lovitus/mosh-go"

	"github.com/flyssh/flyssh/pkg/moshframe"
)

const (
	moshIdleTimeout          = 14 * 24 * time.Hour
	moshTakeoverTokenTimeout = 2 * time.Minute
	maxSessionName           = 64
)

type moshControlRequest struct {
	Op    string `json:"op"`
	Token string `json:"token,omitempty"`
}

type moshStartResponse struct {
	Session       string `json:"session_id"`
	Key           string `json:"key"`
	SocketPath    string `json:"socket_path"`
	PID           int    `json:"pid"`
	TookOver      bool   `json:"took_over"`
	TakeoverToken string `json:"takeover_token,omitempty"`
	Error         string `json:"error,omitempty"`
}

type moshMeta struct {
	Session    string `json:"session"`
	PID        int    `json:"pid"`
	SocketPath string `json:"socket_path"`
	Created    int64  `json:"created"`
	LastAttach int64  `json:"last_attach"`
	TimeoutSec int64  `json:"timeout_sec"`
	Version    int    `json:"version"`
}

type moshDaemonState struct {
	srv     *mosh.Server
	pc      *moshAttachPacketConn
	session string
	paths   moshPaths

	mu      sync.Mutex
	pending map[string]pendingMoshTakeover
}

type pendingMoshTakeover struct {
	prepared *mosh.PreparedTakeover
	expires  time.Time
}

func runMoshStart(session string) {
	resp, err := moshStart(session)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runMoshAttach(session, takeoverToken string) {
	if err := moshAttach(session, takeoverToken); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runMoshDaemon(session string) {
	if err := moshDaemon(session); err != nil {
		os.Exit(1)
	}
}

func moshStart(session string) (*moshStartResponse, error) {
	if err := validateMoshSessionName(session); err != nil {
		return nil, err
	}
	paths, err := moshSessionPaths(session)
	if err != nil {
		return nil, err
	}
	if err := ensureMoshRoot(paths.root); err != nil {
		return nil, err
	}

	unlock, err := lockMoshSession(paths.lock)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if resp, err := callMoshControl(paths.socket, "prepare_takeover", ""); err == nil {
		resp.TookOver = true
		return resp, nil
	} else if !isStaleMoshSocketError(err) {
		return nil, err
	}
	_ = os.Remove(paths.socket)
	_ = os.Remove(paths.meta)

	if err := startMoshDaemon(session); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := callMoshControl(paths.socket, "status", "")
		if err == nil {
			return resp, nil
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	return nil, fmt.Errorf("mosh daemon did not become ready: %w", lastErr)
}

func startMoshDaemon(session string) error {
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer devNull.Close()

	attr := &os.ProcAttr{
		Files: []*os.File{devNull, devNull, devNull},
		Env:   os.Environ(),
		Sys:   &syscall.SysProcAttr{Setsid: true},
	}
	proc, err := os.StartProcess(os.Args[0], []string{os.Args[0], "-mosh-daemon", session}, attr)
	if err != nil {
		return err
	}
	return proc.Release()
}

func moshDaemon(session string) error {
	if err := validateMoshSessionName(session); err != nil {
		return err
	}
	paths, err := moshSessionPaths(session)
	if err != nil {
		return err
	}
	if err := ensureMoshRoot(paths.root); err != nil {
		return err
	}
	_ = os.Remove(paths.socket)

	ln, err := net.Listen("unix", paths.socket)
	if err != nil {
		return err
	}
	defer ln.Close()
	_ = os.Chmod(paths.socket, 0600)

	packetConn := newMoshAttachPacketConn()
	srv, err := mosh.NewServerConn("", packetConn)
	if err != nil {
		return err
	}
	srv.SetNetworkTimeout(moshIdleTimeout)
	defer func() {
		srv.Close()
		_ = os.Remove(paths.socket)
		_ = os.Remove(paths.meta)
	}()

	meta := moshMeta{
		Session:    session,
		PID:        os.Getpid(),
		SocketPath: paths.socket,
		Created:    time.Now().Unix(),
		TimeoutSec: int64(moshIdleTimeout / time.Second),
		Version:    1,
	}
	if err := writeMoshMeta(paths.meta, meta); err != nil {
		return err
	}

	state := &moshDaemonState{
		srv:     srv,
		pc:      packetConn,
		session: session,
		paths:   paths,
		pending: make(map[string]pendingMoshTakeover),
	}
	go acceptMoshControl(ln, state)
	return srv.Serve()
}

func acceptMoshControl(ln net.Listener, state *moshDaemonState) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go state.handleMoshControl(conn)
	}
}

func (s *moshDaemonState) handleMoshControl(conn net.Conn) {
	br := bufio.NewReaderSize(conn, 4096)
	line, err := br.ReadBytes('\n')
	if err != nil {
		conn.Close()
		return
	}
	var req moshControlRequest
	if err := json.Unmarshal(line, &req); err != nil {
		conn.Close()
		return
	}

	switch req.Op {
	case "status":
		_ = json.NewEncoder(conn).Encode(moshStartResponse{
			Session:    s.session,
			Key:        s.srv.KeyBase64(),
			SocketPath: s.paths.socket,
			PID:        os.Getpid(),
		})
		conn.Close()
	case "prepare_takeover":
		resp, err := s.prepareTakeover()
		if err != nil {
			_ = json.NewEncoder(conn).Encode(map[string]string{"error": err.Error()})
			conn.Close()
			return
		}
		_ = json.NewEncoder(conn).Encode(resp)
		conn.Close()
	case "attach":
		var prepared *mosh.PreparedTakeover
		if req.Token != "" {
			var err error
			prepared, err = s.takePreparedTakeover(req.Token)
			if err != nil {
				_, _ = fmt.Fprintf(conn, "ERR %s\n", err)
				conn.Close()
				return
			}
		}
		_ = updateMoshLastAttach(s.paths.meta)
		attach := s.pc.replaceAttach(conn)
		if prepared != nil {
			if err := s.srv.CommitTakeover(prepared); err != nil {
				_, _ = fmt.Fprintf(conn, "ERR %s\n", err)
				attach.close()
				return
			}
		}
		if _, err := conn.Write([]byte("OK\n")); err != nil {
			attach.close()
			return
		}
		for {
			payload, err := moshframe.Read(br)
			if err != nil {
				attach.close()
				return
			}
			if !s.pc.deliverFromAttach(payload) {
				attach.close()
				return
			}
		}
	default:
		conn.Close()
	}
}

func (s *moshDaemonState) prepareTakeover() (*moshStartResponse, error) {
	prepared, err := s.srv.PrepareTakeover()
	if err != nil {
		return nil, err
	}
	token, err := randomMoshTakeoverToken()
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.pruneExpiredTakeoversLocked(time.Now())
	s.pending[token] = pendingMoshTakeover{
		prepared: prepared,
		expires:  time.Now().Add(moshTakeoverTokenTimeout),
	}
	s.mu.Unlock()

	return &moshStartResponse{
		Session:       s.session,
		Key:           prepared.KeyBase64(),
		SocketPath:    s.paths.socket,
		PID:           os.Getpid(),
		TookOver:      true,
		TakeoverToken: token,
	}, nil
}

func (s *moshDaemonState) takePreparedTakeover(token string) (*mosh.PreparedTakeover, error) {
	now := time.Now()
	s.mu.Lock()
	s.pruneExpiredTakeoversLocked(now)
	pending, ok := s.pending[token]
	if ok {
		delete(s.pending, token)
	}
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown or expired takeover token")
	}
	if now.After(pending.expires) {
		return nil, fmt.Errorf("expired takeover token")
	}
	if pending.prepared == nil {
		return nil, fmt.Errorf("prepared takeover is nil")
	}
	return pending.prepared, nil
}

func (s *moshDaemonState) pruneExpiredTakeoversLocked(now time.Time) {
	for token, pending := range s.pending {
		if now.After(pending.expires) {
			delete(s.pending, token)
		}
	}
}

func randomMoshTakeoverToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func moshAttach(session, takeoverToken string) error {
	if err := validateMoshSessionName(session); err != nil {
		return err
	}
	paths, err := moshSessionPaths(session)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("unix", paths.socket, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(moshControlRequest{Op: "attach", Token: takeoverToken}); err != nil {
		return err
	}
	br := bufio.NewReaderSize(conn, 4096)
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != "OK" {
		return fmt.Errorf("attach rejected: %s", strings.TrimSpace(line))
	}

	errCh := make(chan error, 2)
	go func() {
		for {
			payload, err := moshframe.Read(os.Stdin)
			if err != nil {
				errCh <- err
				return
			}
			if err := moshframe.Write(conn, payload); err != nil {
				errCh <- err
				return
			}
		}
	}()
	go func() {
		for {
			payload, err := moshframe.Read(br)
			if err != nil {
				errCh <- err
				return
			}
			if err := moshframe.Write(os.Stdout, payload); err != nil {
				errCh <- err
				return
			}
		}
	}()
	err = <-errCh
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

type moshPaths struct {
	root   string
	socket string
	meta   string
	lock   string
}

func moshSessionPaths(session string) (moshPaths, error) {
	root := filepath.Join(os.TempDir(), fmt.Sprintf("flyssh-mosh-%d", os.Getuid()))
	socket := filepath.Join(root, session+".sock")
	if len(socket) >= 100 {
		return moshPaths{}, fmt.Errorf("mosh socket path too long: %s", socket)
	}
	return moshPaths{
		root:   root,
		socket: socket,
		meta:   filepath.Join(root, session+".json"),
		lock:   filepath.Join(root, session+".lock"),
	}, nil
}

func ensureMoshRoot(root string) error {
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	err := verifyMoshRoot(root)
	if err == nil {
		return nil
	}
	if !isMoshRootModeError(err) {
		return err
	}
	if err := os.Chmod(root, 0700); err != nil {
		return err
	}
	return verifyMoshRoot(root)
}

func verifyMoshRoot(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("mosh runtime directory is a symlink: %s", root)
	}
	if !info.IsDir() {
		return fmt.Errorf("mosh runtime path is not a directory: %s", root)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect mosh runtime directory owner: %s", root)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("mosh runtime directory has unexpected owner: %s", root)
	}
	if info.Mode().Perm() != 0700 {
		return moshRootModeError{root: root, mode: info.Mode().Perm()}
	}
	return nil
}

type moshRootModeError struct {
	root string
	mode os.FileMode
}

func (e moshRootModeError) Error() string {
	return fmt.Sprintf("mosh runtime directory has unsafe permissions: %s (%#o)", e.root, e.mode)
}

func isMoshRootModeError(err error) bool {
	var modeErr moshRootModeError
	return errors.As(err, &modeErr)
}

func validateMoshSessionName(name string) error {
	if name == "" {
		return fmt.Errorf("mosh session name is empty")
	}
	if len(name) > maxSessionName {
		return fmt.Errorf("mosh session name is too long")
	}
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			continue
		}
		return fmt.Errorf("invalid mosh session name %q", name)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("invalid mosh session name %q", name)
	}
	return nil
}

func lockMoshSession(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

func callMoshControl(socket, op, token string) (*moshStartResponse, error) {
	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		return nil, staleMoshSocketError{err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if err := json.NewEncoder(conn).Encode(moshControlRequest{Op: op, Token: token}); err != nil {
		return nil, err
	}
	var resp moshStartResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("mosh control %s: %s", op, resp.Error)
	}
	if resp.Key == "" {
		return nil, fmt.Errorf("mosh control returned empty key")
	}
	return &resp, nil
}

type staleMoshSocketError struct {
	err error
}

func (e staleMoshSocketError) Error() string {
	return e.err.Error()
}

func (e staleMoshSocketError) Unwrap() error {
	return e.err
}

func isStaleMoshSocketError(err error) bool {
	var stale staleMoshSocketError
	return errors.As(err, &stale)
}

func writeMoshMeta(path string, meta moshMeta) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	encErr := json.NewEncoder(f).Encode(meta)
	closeErr := f.Close()
	if encErr != nil {
		_ = os.Remove(tmp)
		return encErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, path)
}

func updateMoshLastAttach(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var meta moshMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return err
	}
	meta.LastAttach = time.Now().Unix()
	return writeMoshMeta(path, meta)
}

type moshAttachPacketConn struct {
	mu       sync.Mutex
	incoming chan []byte
	attach   *moshAttachSession
	closed   chan struct{}
	deadline time.Time
}

type moshAttachSession struct {
	conn net.Conn
	out  chan []byte
	done chan struct{}
}

func newMoshAttachPacketConn() *moshAttachPacketConn {
	return &moshAttachPacketConn{
		incoming: make(chan []byte, 256),
		closed:   make(chan struct{}),
	}
}

func (c *moshAttachPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()
	var timer <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, nil, os.ErrDeadlineExceeded
		}
		timer = time.After(d)
	}
	select {
	case payload := <-c.incoming:
		return copy(p, payload), mosh.PacketAddr("client"), nil
	case <-timer:
		return 0, nil, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *moshAttachPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	attach := c.attach
	c.mu.Unlock()
	if attach == nil {
		return len(p), nil
	}
	payload := append([]byte(nil), p...)
	select {
	case attach.out <- payload:
	default:
	}
	return len(p), nil
}

func (c *moshAttachPacketConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	c.kickAttach()
	return nil
}

func (c *moshAttachPacketConn) LocalAddr() net.Addr { return mosh.PacketAddr("127.0.0.1:0") }

func (c *moshAttachPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *moshAttachPacketConn) replaceAttach(conn net.Conn) *moshAttachSession {
	next := &moshAttachSession{
		conn: conn,
		out:  make(chan []byte, 256),
		done: make(chan struct{}),
	}
	c.mu.Lock()
	old := c.attach
	c.attach = next
	c.mu.Unlock()
	if old != nil {
		old.close()
	}
	go func() {
		defer next.close()
		for {
			select {
			case payload := <-next.out:
				if err := moshframe.Write(conn, payload); err != nil {
					return
				}
			case <-next.done:
				return
			}
		}
	}()
	return next
}

func (c *moshAttachPacketConn) kickAttach() {
	c.mu.Lock()
	old := c.attach
	c.attach = nil
	c.mu.Unlock()
	if old != nil {
		old.close()
	}
}

func (c *moshAttachPacketConn) deliverFromAttach(payload []byte) bool {
	payload = append([]byte(nil), payload...)
	select {
	case c.incoming <- payload:
		return true
	case <-c.closed:
		return false
	default:
		return true
	}
}

func (a *moshAttachSession) close() {
	select {
	case <-a.done:
	default:
		close(a.done)
		_ = a.conn.Close()
	}
}

var _ mosh.PacketConn = (*moshAttachPacketConn)(nil)
