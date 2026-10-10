//go:build !windows

package e2e_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/flyssh/flyssh/internal/testkit"
	"github.com/flyssh/flyssh/pkg/gateway"
	"golang.org/x/crypto/ssh"
)

func TestGUIGatewayEndpointSurvivesNetworkFailure(t *testing.T) {
	bin := os.Getenv("FLYSSH_RECOVERY_BIN")
	if bin == "" {
		t.Skip("requires a built FlySSH executable")
	}
	for _, mode := range []string{"reset", "silent-blackhole"} {
		t.Run(mode, func(t *testing.T) {
			first := testkit.StartSSHServer(t, map[string]string{"user": "password"})
			last := testkit.StartSSHServer(t, map[string]string{"user": "password"})
			proxy := testkit.StartFaultProxy(t, first.Addr)
			cmd := exec.Command(bin, "user:password@"+proxy.Addr(), "user:password@"+last.Addr,
				"-o", "StrictHostKeyChecking=no", "-o", "ServerAliveInterval=1",
				"--reconnect-delay", "1", "--gui-internal-gateway", "local:password@127.0.0.1:0")
			cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			stderr := &lockedBuffer{}
			cmd.Stderr = stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
			ready := make(chan gateway.ReadyInfo, 1)
			readyErr := make(chan error, 1)
			go func() {
				var info gateway.ReadyInfo
				if err := json.NewDecoder(stdout).Decode(&info); err != nil {
					readyErr <- err
					return
				}
				ready <- info
			}()
			var info gateway.ReadyInfo
			select {
			case info = <-ready:
			case err := <-readyErr:
				t.Fatalf("gateway startup: %v\n%s", err, stderr.String())
			case <-time.After(15 * time.Second):
				t.Fatalf("gateway startup timeout\n%s", stderr.String())
			}
			client := dialRecoveryGateway(t, info)
			assertGatewayCommand(t, client, "before-cut")
			dead := make(chan error, 1)
			go func() { dead <- client.Wait() }()
			if mode == "reset" {
				proxy.Cut()
			} else {
				proxy.Blackhole(true)
			}
			select {
			case <-dead:
			case <-time.After(10 * time.Second):
				client.Close()
				t.Fatalf("dead upstream left downstream hanging\n%s", stderr.String())
			}
			client.Close()
			proxy.Blackhole(false)
			// A client reconnects to the original address with exactly the same
			// password and pinned key; no second readiness message is consumed.
			reconnected := dialRecoveryGateway(t, info)
			defer reconnected.Close()
			assertGatewayCommand(t, reconnected, "after-cut")
			if proxy.Connections.Load() < 2 {
				t.Fatal("upstream route was not rebuilt")
			}
			// Exercise binary channel data after reconnect, not only an exec reply.
			session, err := reconnected.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			payload := strings.Repeat("binary\x00payload\xff\n", 65536)
			session.Stdin = strings.NewReader(payload)
			data, err := session.Output("cat")
			if err != nil || string(data) != payload {
				t.Fatalf("binary transfer after reconnect: length=%d err=%v", len(data), err)
			}
			// Closing the gateway process must release the listener as well.
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			if conn, err := net.DialTimeout("tcp", info.Address, time.Second); err == nil {
				conn.Close()
				t.Fatal("gateway port remains open after process exit")
			}
		})
	}
}

func dialRecoveryGateway(t *testing.T, info gateway.ReadyInfo) *ssh.Client {
	t.Helper()
	conn, err := net.DialTimeout("tcp", info.Address, 5*time.Second)
	if err != nil {
		t.Fatalf("original gateway endpoint is unavailable: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	c, chans, reqs, err := ssh.NewClientConn(conn, info.Address, &ssh.ClientConfig{
		User: "local", Auth: []ssh.AuthMethod{ssh.Password("password")},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if !slices.Contains(info.HostKeys, ssh.FingerprintSHA256(key)) {
				return fmt.Errorf("gateway host key changed")
			}
			return nil
		},
	})
	if err != nil {
		conn.Close()
		t.Fatalf("reconnect to original gateway: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	return ssh.NewClient(c, chans, reqs)
}

func assertGatewayCommand(t *testing.T, client *ssh.Client, text string) {
	t.Helper()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	session.Stdin = strings.NewReader(text)
	reader, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Start("cat"); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Wait(); err != nil {
		t.Fatal(err)
	}
	if string(data) != text {
		t.Fatalf("gateway output %q, want %q", data, text)
	}
}
