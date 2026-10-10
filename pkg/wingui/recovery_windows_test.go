//go:build windows

package wingui

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/flyssh/flyssh/internal/testkit"
)

// These tests run the actual GUI handlers, FlySSH children, Windows Job
// Objects, MSYS2 rsync and SSH server. No transfer runner is replaced.
func TestGUIRsyncRecovery(t *testing.T) {
	for _, upload := range []bool{true, false} {
		name := "download"
		if upload {
			name = "upload"
		}
		t.Run(name, func(t *testing.T) {
			a, proxy, source, target, payload := recoveryTransfer(t)
			remoteSource := msysTestPath(source)
			remoteTarget := msysTestPath(target)
			sources, dest := []string{source}, remoteTarget
			if !upload {
				sources, dest = []string{remoteSource}, target
			}
			flag, raw, err := buildTransferArgs("rsync", upload, false, sources, dest)
			if err != nil {
				t.Fatal(err)
			}
			targetFile := filepath.Join(target, filepath.Base(source))
			previous := []byte("previous complete version")
			if err := os.WriteFile(targetFile, previous, 0600); err != nil {
				t.Fatal(err)
			}
			proxy.CutAfter(1024 * 1024)
			a.runTransferArgs(buildChildArgs(a.rawArgs, flag, "--bwlimit=1024 "+raw))
			select {
			case <-proxy.CutDone:
			case <-time.After(30 * time.Second):
				t.Fatal("real rsync did not reach the injected disconnect")
			}
			partial := filepath.Join(target, ".flyssh-partial", filepath.Base(source))
			waitRecovery(t, 15*time.Second, "partial file retained after disconnect", func() bool {
				info, err := os.Stat(partial)
				return err == nil && info.Size() > 0
			})
			if data, err := os.ReadFile(targetFile); err != nil || !bytes.Equal(data, previous) {
				t.Fatalf("interrupted upload replaced the complete destination: %v", err)
			}
			waitRecovery(t, 60*time.Second, "rsync recovery completion", func() bool {
				a.mu.Lock()
				defer a.mu.Unlock()
				return !a.busy
			})
			data, err := os.ReadFile(targetFile)
			if err != nil {
				t.Fatal(err)
			}
			if sha256.Sum256(data) != sha256.Sum256(payload) {
				t.Fatal("recovered file checksum mismatch")
			}
			if proxy.Connections.Load() < 2 {
				t.Fatal("rsync did not reconnect")
			}
			if _, err := os.Stat(partial); !os.IsNotExist(err) {
				t.Fatalf("completed partial file remains: %v", err)
			}
		})
	}
}

func TestGUIRsyncCancel(t *testing.T) {
	for _, phase := range []string{"transfer", "backoff"} {
		t.Run(phase, func(t *testing.T) {
			a, proxy, source, target, _ := recoveryTransfer(t)
			flag, raw, err := buildTransferArgs("rsync", true, false, []string{source}, msysTestPath(target))
			if err != nil {
				t.Fatal(err)
			}
			if phase == "backoff" {
				proxy.CutAfter(256 * 1024)
			}
			a.runTransferArgs(buildChildArgs(a.rawArgs, flag, "--bwlimit=128 "+raw))
			waitRecovery(t, 15*time.Second, "running rsync child", func() bool {
				a.mu.Lock()
				defer a.mu.Unlock()
				return a.busy && a.current != nil
			})
			if phase == "backoff" {
				select {
				case <-proxy.CutDone:
				case <-time.After(30 * time.Second):
					t.Fatal("disconnect not reached")
				}
				waitRecovery(t, 10*time.Second, "retry backoff", func() bool {
					a.mu.Lock()
					defer a.mu.Unlock()
					return a.busy && a.current == nil
				})
			} else {
				waitRecovery(t, 15*time.Second, "file bytes flowing through SSH", func() bool { return proxy.Transferred() > 256*1024 })
			}
			// This is the Cancel button callback, also used by window close.
			a.killCurrent()
			waitRecovery(t, 5*time.Second, "cancelled operation released GUI", func() bool {
				a.mu.Lock()
				defer a.mu.Unlock()
				return !a.busy && a.current == nil
			})
			count := proxy.Connections.Load()
			time.Sleep(4 * time.Second)
			if proxy.Connections.Load() != count {
				t.Fatal("cancelled operation started another SSH connection")
			}
			if _, err := os.Stat(filepath.Join(target, filepath.Base(source))); !os.IsNotExist(err) {
				t.Fatal("cancelled transfer published an incomplete destination")
			}
		})
	}
}

func recoveryTransfer(t *testing.T) (*app, *testkit.FaultProxy, string, string, []byte) {
	t.Helper()
	bin := os.Getenv("FLYSSH_RECOVERY_BIN")
	if bin == "" {
		t.Skip("requires a built Windows FlySSH and real rsync")
	}
	if _, err := resolveRsyncBinary(); err != nil {
		t.Fatal(err)
	}
	// The fixture's remote SSH server also runs on Windows. Keep its POSIX
	// operands intact when MSYS2 rsync launches the native FlySSH transport.
	t.Setenv("MSYS2_ARG_CONV_EXCL", "*")
	server := testkit.StartSSHServer(t, map[string]string{"user": "password"})
	proxy := testkit.StartFaultProxy(t, server.Addr)
	dir, target := t.TempDir(), t.TempDir()
	source := filepath.Join(dir, "business.jar")
	payload := make([]byte, 8*1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	a := &app{exe: bin, rawArgs: []string{"user:password@" + proxy.Addr(), "-o", "StrictHostKeyChecking=no"},
		localNav: navState{Current: dir}, remoteNav: navState{Current: msysTestPath(target)}}
	t.Cleanup(func() { a.killCurrent(); a.killShellGateway() })
	return a, proxy, source, target, payload
}

func msysTestPath(path string) string {
	p := filepath.ToSlash(path)
	return "/" + strings.ToLower(p[:1]) + p[2:]
}

func waitRecovery(t *testing.T, timeout time.Duration, description string, ready func() bool) {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ready() {
			return
		}
		select {
		case <-timer.C:
			t.Fatalf("timed out: %s", description)
		case <-ticker.C:
		}
	}
}
