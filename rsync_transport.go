package main

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

func abortRsyncTransports(clients []*ssh.Client) {
	for _, client := range clients {
		_ = client.Close()
	}
}

// waitRsyncTransport coordinates the two independent ends of the transport.
// stdin can remain open after the remote command exits. Do not join that read:
// this helper is used only by the one-shot internal transport process, whose
// exit releases the inherited input handle and any pending read.
func waitRsyncTransport(input io.ReadCloser, remoteInput io.WriteCloser, wait func() error, abort func()) error {
	inputDone := make(chan error, 1)
	go func() {
		defer input.Close()
		n, err := io.Copy(remoteInput, input)
		if err != nil {
			// Report before Close: SSH channel EOF writes can themselves block.
			inputDone <- fmt.Errorf("rsync transport input failed after %d bytes: %w", n, err)
			return
		}
		// x/crypto/ssh returns io.EOF from CloseWrite if the peer already
		// closed the channel. After clean input EOF this is normal teardown;
		// the remote command's result remains authoritative.
		if err := remoteInput.Close(); err != nil && !errors.Is(err, io.EOF) {
			inputDone <- fmt.Errorf("rsync transport close input: %w", err)
			return
		}
		inputDone <- nil
	}()
	remoteDone := make(chan error, 1)
	go func() { remoteDone <- wait() }()

	select {
	case err := <-inputDone:
		if err != nil {
			// A remote nonzero exit can close its input while copying is still
			// in flight. Preserve an already available remote exit status.
			select {
			case remoteErr := <-remoteDone:
				if remoteErr != nil {
					return remoteErr
				}
			default:
			}
			abort()
			return err
		}
		return <-remoteDone
	case err := <-remoteDone:
		// Preserve a real remote failure. A completed local failure must not
		// be erased by a successful remote exit.
		if err == nil {
			select {
			case inputErr := <-inputDone:
				if inputErr != nil {
					abort()
					return inputErr
				}
			default:
			}
		}
		return err
	}
}
