//go:build linux || darwin || freebsd

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mosh "github.com/lovitus/mosh-go"
)

func TestValidateMoshSessionName(t *testing.T) {
	for _, name := range []string{"work", "a.b_c-1", "中文", "", ".", "..", "a/b", "a\\b", "~", "a b"} {
		err := validateMoshSessionName(name)
		valid := name == "work" || name == "a.b_c-1"
		if valid && err != nil {
			t.Fatalf("%q should be valid: %v", name, err)
		}
		if !valid && err == nil {
			t.Fatalf("%q should be invalid", name)
		}
	}
}

func TestMoshSessionPaths(t *testing.T) {
	paths, err := moshSessionPaths("work")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(paths.socket) != "work.sock" {
		t.Fatalf("socket path = %s", paths.socket)
	}
	if filepath.Base(paths.meta) != "work.json" {
		t.Fatalf("meta path = %s", paths.meta)
	}
	if filepath.Base(paths.lock) != "work.lock" {
		t.Fatalf("lock path = %s", paths.lock)
	}
}

func TestWriteAndUpdateMoshMeta(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "work.json")
	meta := moshMeta{Session: "work", PID: os.Getpid(), SocketPath: filepath.Join(dir, "work.sock")}
	if err := writeMoshMeta(path, meta); err != nil {
		t.Fatal(err)
	}
	if err := updateMoshLastAttach(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("metadata file is empty")
	}
}

func TestEnsureMoshRootTightensOwnedDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := ensureMoshRoot(root); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0700 {
		t.Fatalf("mode = %#o, want 0700", got)
	}
}

func TestEnsureMoshRootRejectsSymlinkWithoutChmodTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "runtime-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	err := ensureMoshRoot(link)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("error = %v, want symlink rejection", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0755 {
		t.Fatalf("target mode = %#o, want unchanged 0755", got)
	}
}

func TestCallMoshControlClassifiesDialFailureAsStale(t *testing.T) {
	_, err := callMoshControl(filepath.Join(t.TempDir(), "missing.sock"), "status", "")
	if err == nil {
		t.Fatal("expected error")
	}
	if !isStaleMoshSocketError(err) {
		t.Fatalf("error = %T %[1]v, want stale socket error", err)
	}
}

func TestCallMoshControlDoesNotClassifyControlErrorAsStale(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "flyssh-mosh-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req moshControlRequest
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}
		_ = json.NewEncoder(conn).Encode(moshStartResponse{Error: "takeover failed"})
	}()

	_, err = callMoshControl(socket, "prepare_takeover", "")
	if err == nil {
		t.Fatal("expected error")
	}
	if isStaleMoshSocketError(err) {
		t.Fatalf("error = %T %[1]v, should not be stale", err)
	}
	if !strings.Contains(err.Error(), "takeover failed") {
		t.Fatalf("error = %v, want control error", err)
	}
	<-done
}

func TestMoshAttachForwardsOKToStdout(t *testing.T) {
	session := fmt.Sprintf("attach-ok-%d", time.Now().UnixNano())
	paths, err := moshSessionPaths(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureMoshRoot(paths.root); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(paths.socket)
	defer os.Remove(paths.socket)

	ln, err := net.Listen("unix", paths.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	reqCh := make(chan moshControlRequest, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req moshControlRequest
		if err := json.NewDecoder(conn).Decode(&req); err == nil {
			reqCh <- req
		}
		_, _ = conn.Write([]byte("OK\n"))
		_, _ = io.Copy(io.Discard, conn)
	}()

	oldStdin := os.Stdin
	oldStdout := os.Stdout
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = stdinR
	os.Stdout = stdoutW
	defer func() {
		os.Stdin = oldStdin
		os.Stdout = oldStdout
		_ = stdinR.Close()
		_ = stdoutR.Close()
	}()
	_ = stdinW.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- moshAttach(session, "")
		_ = stdoutW.Close()
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("moshAttach returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("moshAttach did not return")
	}

	out, err := io.ReadAll(stdoutR)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "OK\n" {
		t.Fatalf("stdout = %q, want OK newline", out)
	}
	select {
	case req := <-reqCh:
		if req.Op != "attach" {
			t.Fatalf("request op = %q, want attach", req.Op)
		}
	default:
		t.Fatal("server did not receive attach request")
	}
}

func TestPrepareTakeoverDefersCommitUntilTokenAttach(t *testing.T) {
	pc := newMoshAttachPacketConn()
	srv, err := mosh.NewServerConn("", pc)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	state := &moshDaemonState{
		srv:     srv,
		pc:      pc,
		session: "work",
		paths:   moshPaths{socket: filepath.Join(t.TempDir(), "work.sock")},
		pending: make(map[string]pendingMoshTakeover),
	}
	oldKey := srv.KeyBase64()
	resp, err := state.prepareTakeover()
	if err != nil {
		t.Fatal(err)
	}
	if resp.TakeoverToken == "" {
		t.Fatal("missing takeover token")
	}
	if resp.Key == "" || resp.Key == oldKey {
		t.Fatalf("prepared key = %q, old key = %q", resp.Key, oldKey)
	}
	if got := srv.KeyBase64(); got != oldKey {
		t.Fatalf("server key changed before commit: %q != %q", got, oldKey)
	}
	if _, err := state.takePreparedTakeover("bad-token"); err == nil {
		t.Fatal("bad token should be rejected")
	}
	if got := srv.KeyBase64(); got != oldKey {
		t.Fatalf("server key changed after bad token: %q != %q", got, oldKey)
	}
	prepared, err := state.takePreparedTakeover(resp.TakeoverToken)
	if err != nil {
		t.Fatal(err)
	}
	if got := srv.KeyBase64(); got != oldKey {
		t.Fatalf("server key changed before explicit commit: %q != %q", got, oldKey)
	}
	if _, err := state.takePreparedTakeover(resp.TakeoverToken); err == nil {
		t.Fatal("takeover token should be single-use")
	}
	if err := srv.CommitTakeover(prepared); err != nil {
		t.Fatal(err)
	}
	if got := srv.KeyBase64(); got != resp.Key {
		t.Fatalf("server key after commit = %q, want %q", got, resp.Key)
	}
}

func TestDeliverFromAttachDropsWhenIncomingQueueIsFull(t *testing.T) {
	pc := newMoshAttachPacketConn()
	for i := 0; i < cap(pc.incoming); i++ {
		pc.incoming <- []byte{byte(i)}
	}
	done := make(chan bool, 1)
	go func() {
		done <- pc.deliverFromAttach([]byte("drop"))
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("deliverFromAttach returned false for an open conn")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("deliverFromAttach blocked on a full incoming queue")
	}
}
