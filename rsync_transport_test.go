package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/crypto/ssh"
)

type orderedTransportConn struct {
	ssh.Conn
	close func() error
}

func (c orderedTransportConn) Close() error { return c.close() }

func TestAbortRsyncTransportsClosesOutermostBeforeNestedChannels(t *testing.T) {
	outerClosed := false
	outer := &ssh.Client{Conn: orderedTransportConn{close: func() error { outerClosed = true; return nil }}}
	inner := &ssh.Client{Conn: orderedTransportConn{close: func() error {
		if !outerClosed {
			t.Error("inner channel close could block before outer transport was aborted")
		}
		return nil
	}}}
	abortRsyncTransports([]*ssh.Client{outer, inner})
	if !outerClosed {
		t.Fatal("outer transport not closed")
	}
}

type transportTestWriter struct {
	bytes.Buffer
	closed chan struct{}
}

func (w *transportTestWriter) Close() error { close(w.closed); return nil }

type eofCloseWriter struct{ bytes.Buffer }

func (*eofCloseWriter) Close() error { return io.EOF }

func TestRsyncTransportPeerCloseEOFPreservesRemoteSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		remote := &eofCloseWriter{}
		allowWait := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- waitRsyncTransport(io.NopCloser(strings.NewReader("payload")), remote, func() error { <-allowWait; return nil }, func() { t.Error("clean EOF teardown aborted transport") })
		}()
		// All goroutines are durably blocked: CloseWrite has returned EOF,
		// while the remote exit status is deliberately still unavailable.
		synctest.Wait()
		close(allowWait)
		if err := <-done; err != nil {
			t.Fatalf("remote success replaced by teardown EOF: %v", err)
		}
	})
}

type partialFailureReader struct{ err error }

func (r partialFailureReader) Read(p []byte) (int, error) { return copy(p, "partial"), r.err }

func TestRsyncTransportInputFailureAbortsWithoutClosingChannelFirst(t *testing.T) {
	failure := errors.New("input handle failed")
	aborted := make(chan struct{})
	remote := &transportTestWriter{closed: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- waitRsyncTransport(io.NopCloser(partialFailureReader{failure}), remote,
			func() error { <-aborted; return errors.New("transport closed") }, func() { close(aborted) })
	}()
	select {
	case err := <-done:
		if !errors.Is(err, failure) || !strings.Contains(err.Error(), "7 bytes") {
			t.Fatalf("input error lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("input failure did not abort")
	}
	if remote.String() != "partial" {
		t.Fatalf("partial bytes lost: %q", remote.String())
	}
	select {
	case <-remote.closed:
		t.Fatal("failed input attempted channel EOF before abort")
	default:
	}
}

func TestRsyncTransportEOFWaitsForRemoteResult(t *testing.T) {
	remote := &transportTestWriter{closed: make(chan struct{})}
	release := make(chan struct{})
	failure := errors.New("remote exit 23")
	done := make(chan error, 1)
	go func() {
		done <- waitRsyncTransport(io.NopCloser(strings.NewReader("payload")), remote,
			func() error { <-release; return failure }, func() { t.Error("EOF aborted transport") })
	}()
	select {
	case <-remote.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("EOF not delivered")
	}
	select {
	case err := <-done:
		t.Fatalf("did not wait for remote: %v", err)
	default:
	}
	close(release)
	select {
	case err := <-done:
		if !errors.Is(err, failure) {
			t.Fatalf("remote error lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("remote completion lost")
	}
}

func TestRsyncTransportRemoteExitDoesNotWaitForInheritedInput(t *testing.T) {
	input, producer := io.Pipe()
	defer producer.Close()
	remote := &transportTestWriter{closed: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- waitRsyncTransport(input, remote, func() error { return nil }, func() { t.Error("unexpected abort") })
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("remote exit joined a still-open input pipe")
	}
	// The real one-shot process exits here. Release the test's inherited-input
	// stand-in so its copy worker can finish as well.
	_ = producer.Close()
	select {
	case <-remote.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("copy worker did not finish")
	}
}
