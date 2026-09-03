package transfer

import (
	"context"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func Run(client *ssh.Client, spec *Spec) (int, error) {
	if spec == nil {
		return 0, nil
	}
	switch spec.Mode {
	case ModeSCP:
		return runSCP(client, spec)
	case ModeRsync:
		return 1, fmt.Errorf("rsync transfer mode is not implemented in SSH-session mode")
	default:
		return 1, fmt.Errorf("unsupported transfer mode: %s", spec.Mode)
	}
}

// RunContext runs a transfer and aborts its SSH connection when the context is
// cancelled. Closing the client is deliberately broad: it guarantees that SCP
// subprocesses, forwarded channels, and blocked network I/O do not survive a
// cancelled transfer. Callers should reconnect before reusing the route.
func RunContext(ctx context.Context, client *ssh.Client, spec *Spec) (int, error) {
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	type result struct {
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		code, err := Run(client, spec)
		done <- result{code: code, err: err}
	}()
	select {
	case result := <-done:
		return result.code, result.err
	case <-ctx.Done():
		_ = client.Close()
		<-done
		return 1, ctx.Err()
	}
}
