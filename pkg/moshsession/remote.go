package moshsession

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/flyssh/flyssh/pkg/forwarding"
	"github.com/flyssh/flyssh/pkg/moshframe"
	"golang.org/x/crypto/ssh"
)

const attachHandshakeTimeout = 10 * time.Second

type StartInfo struct {
	Session       string `json:"session_id"`
	Key           string `json:"key"`
	SocketPath    string `json:"socket_path"`
	PID           int    `json:"pid"`
	TookOver      bool   `json:"took_over"`
	TakeoverToken string `json:"takeover_token,omitempty"`
}

type Attach struct {
	session *ssh.Session
	stdin   io.WriteCloser
	done    chan error
	closed  chan struct{}
	once    sync.Once
}

func StartRemote(client *ssh.Client, sessionName string, verbose bool) (*StartInfo, error) {
	relayPath, err := forwarding.EnsureRelay(client, verbose)
	if err != nil {
		return nil, err
	}
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	var stderr bytes.Buffer
	sess.Stderr = &stderr
	out, err := sess.Output(shellQuote(relayPath) + " -mosh-start " + shellQuote(sessionName))
	if err != nil {
		if s := strings.TrimSpace(stderr.String()); s != "" {
			return nil, fmt.Errorf("mosh start: %s: %w", s, err)
		}
		return nil, fmt.Errorf("mosh start: %w", err)
	}
	var info StartInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, fmt.Errorf("parse mosh start response: %w: %q", err, string(out))
	}
	if info.Key == "" {
		return nil, fmt.Errorf("mosh start returned empty key")
	}
	return &info, nil
}

func AttachRemote(client *ssh.Client, sessionName string, takeoverToken string, conn *tunnelConn, verbose bool) (*Attach, error) {
	relayPath, err := forwarding.EnsureRelay(client, verbose)
	if err != nil {
		return nil, err
	}
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, err
	}
	sess.Stderr = os.Stderr

	cmd := moshAttachCommand(relayPath, sessionName, takeoverToken)
	if err := sess.Start(cmd); err != nil {
		sess.Close()
		return nil, err
	}
	br := bufio.NewReaderSize(stdout, 4096)
	if err := consumeAttachOKWithTimeout(br, attachHandshakeTimeout); err != nil {
		_ = sess.Close()
		return nil, err
	}

	a := &Attach{session: sess, stdin: stdin, done: make(chan error, 1), closed: make(chan struct{})}
	go func() {
		for {
			select {
			case payload := <-conn.writeCh:
				if err := moshframe.Write(stdin, payload); err != nil {
					_ = sess.Close()
					return
				}
			case <-conn.closed:
				_ = stdin.Close()
				return
			case <-a.closed:
				_ = stdin.Close()
				return
			}
		}
	}()
	go func() {
		for {
			payload, err := moshframe.Read(br)
			if err != nil {
				_ = sess.Close()
				return
			}
			if !conn.deliver(payload) {
				_ = sess.Close()
				return
			}
		}
	}()
	go func() {
		a.done <- sess.Wait()
	}()
	return a, nil
}

func consumeAttachOK(r *bufio.Reader) error {
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != "OK" {
		return fmt.Errorf("attach rejected: %s", strings.TrimSpace(line))
	}
	return nil
}

func consumeAttachOKWithTimeout(r *bufio.Reader, timeout time.Duration) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- consumeAttachOK(r)
	}()
	select {
	case err := <-errCh:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("attach handshake timed out after %s", timeout)
	}
}

func (a *Attach) Wait() error {
	return <-a.done
}

func (a *Attach) Close() {
	a.once.Do(func() {
		close(a.closed)
		_ = a.stdin.Close()
		_ = a.session.Close()
	})
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func moshAttachCommand(relayPath, sessionName, takeoverToken string) string {
	cmd := shellQuote(relayPath) + " -mosh-attach " + shellQuote(sessionName)
	if takeoverToken != "" {
		cmd += " " + shellQuote(takeoverToken)
	}
	return cmd
}
