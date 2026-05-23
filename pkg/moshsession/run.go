package moshsession

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	mosh "github.com/lovitus/mosh-go"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type Connector func() (*ssh.Client, func(), error)

type Options struct {
	SessionName    string
	ReconnectDelay time.Duration
	Verbose        bool
}

func Run(ctx context.Context, connector Connector, opts Options) error {
	sessionName := opts.SessionName
	if sessionName == "" {
		var err error
		sessionName, err = randomSessionName()
		if err != nil {
			return err
		}
	}
	if opts.ReconnectDelay <= 0 {
		opts.ReconnectDelay = 3 * time.Second
	}

	restoreVT := enableVTProcessing()
	defer restoreVT()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	client, cleanup, err := connector()
	if err != nil {
		return err
	}
	info, err := StartRemote(client, sessionName, opts.Verbose)
	if err != nil {
		cleanup()
		return err
	}
	fmt.Fprintf(os.Stderr, "flyssh: mosh session %s pid=%d\n", info.Session, info.PID)

	rawKey, err := decodeMoshKey(info.Key)
	if err != nil {
		cleanup()
		return err
	}
	ocb, err := mosh.NewOCB(rawKey)
	if err != nil {
		cleanup()
		return err
	}
	tunnel := newTunnelConn()
	moshClient, err := mosh.DialConn(tunnel, ocb)
	if err != nil {
		cleanup()
		return err
	}
	defer moshClient.Close()

	attach, err := AttachRemote(client, sessionName, info.TakeoverToken, tunnel, opts.Verbose)
	if err != nil {
		cleanup()
		return fmt.Errorf("attach remote mosh session: %w", err)
	}
	attachCleanup := cleanup

	var oldState *term.State
	restoreVTInput := func() {}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		oldState, err = term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil && opts.Verbose {
			fmt.Fprintf(os.Stderr, "flyssh: warning: could not set raw terminal: %v\n", err)
		}
		if err == nil {
			restoreVTInput = enableVTInput()
		}
	}
	defer func() {
		restoreVTInput()
		if oldState != nil {
			_ = term.Restore(int(os.Stdin.Fd()), oldState)
		}
	}()

	done := make(chan struct{})
	defer close(done)
	go copyInput(done, moshClient)
	go copyOutput(done, moshClient)
	go resizeLoop(done, moshClient)

	for {
		err, retry := waitAttach(ctx, sigCh, attach.Wait, attach.Close)
		attachCleanup()
		if !retry {
			return err
		}
		fmt.Fprintf(os.Stderr, "\rflyssh: mosh attach disconnected: %v; reconnecting in %v...\n", err, opts.ReconnectDelay)
		for {
			if err := waitReconnect(ctx, sigCh, opts.ReconnectDelay); err != nil {
				return err
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case sig := <-sigCh:
				return fmt.Errorf("interrupted by %s", sig)
			default:
			}

			client, cleanup, err := connector()
			if err != nil {
				fmt.Fprintf(os.Stderr, "\rflyssh: mosh reconnect failed: %v\n", err)
				continue
			}
			attach, err = AttachRemote(client, sessionName, "", tunnel, opts.Verbose)
			if err != nil {
				cleanup()
				return fmt.Errorf("attach remote mosh session: %w", err)
			}
			attachCleanup = cleanup
			break
		}
	}
}

func waitAttach(ctx context.Context, sigCh <-chan os.Signal, wait func() error, closeAttach func()) (error, bool) {
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- wait()
	}()

	select {
	case err := <-waitCh:
		closeAttach()
		return err, err != nil
	case <-ctx.Done():
		closeAttach()
		return ctx.Err(), false
	case sig := <-sigCh:
		closeAttach()
		return fmt.Errorf("interrupted by %s", sig), false
	}
}

func waitReconnect(ctx context.Context, sigCh <-chan os.Signal, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case sig := <-sigCh:
		return fmt.Errorf("interrupted by %s", sig)
	}
}

func copyInput(done <-chan struct{}, client *mosh.Client) {
	buf := make([]byte, 4096)
	for {
		select {
		case <-done:
			return
		default:
		}
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			client.Send(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func copyOutput(done <-chan struct{}, client *mosh.Client) {
	for {
		select {
		case <-done:
			return
		default:
		}
		out := client.Recv(100 * time.Millisecond)
		if len(out) > 0 {
			_, _ = os.Stdout.Write(out)
		}
	}
}

func resizeLoop(done <-chan struct{}, client *mosh.Client) {
	w, h := terminalSize()
	client.Resize(uint16(w), uint16(h))
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			nw, nh := terminalSize()
			if nw != w || nh != h {
				w, h = nw, nh
				client.Resize(uint16(w), uint16(h))
			}
		}
	}
}

func terminalSize() (int, int) {
	for _, fd := range []int{int(os.Stdout.Fd()), int(os.Stdin.Fd())} {
		if term.IsTerminal(fd) {
			if w, h, err := term.GetSize(fd); err == nil && w > 0 && h > 0 {
				return w, h
			}
		}
	}
	return 80, 24
}

func randomSessionName() (string, error) {
	var b [8]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	return "flyssh-" + hex.EncodeToString(b[:]), nil
}

func decodeMoshKey(key string) ([]byte, error) {
	for len(key)%4 != 0 {
		key += "="
	}
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("bad mosh key: %w", err)
	}
	return raw, nil
}
