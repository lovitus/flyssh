package main

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryableForwardErrorOnlyRetriesListenerSetup(t *testing.T) {
	if !retryableForwardError("local", errors.New("listen on 127.0.0.1:1234: address already in use")) {
		t.Fatal("expected local listener conflict to be retryable")
	}
	if !retryableForwardError("dynamic", errors.New("dynamic forward listen on 127.0.0.1:1234: bind failed")) {
		t.Fatal("expected dynamic listener failure to be retryable")
	}
	if retryableForwardError("local", errors.New("invalid local forward spec")) {
		t.Fatal("invalid local forward spec must not be retried")
	}
	if retryableForwardError("local", errors.New("accept: use of closed network connection")) {
		t.Fatal("closed listener must not be retried")
	}
	if retryableForwardError("remote", errors.New("remote listen on 127.0.0.1:1234: denied")) {
		t.Fatal("remote forwarding keeps its existing failure semantics")
	}
	if retryableForwardError("local", net.ErrClosed) {
		t.Fatal("net.ErrClosed must not be retried")
	}
}

func TestRunForwardWithRetryRetriesUntilReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		runForwardWithRetry(ctx, "local", "127.0.0.1:1234", func() error {
			if calls.Add(1) == 1 {
				return errors.New("listen on 127.0.0.1:1234: address already in use")
			}
			return nil
		}, nil)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("forward retry did not reach ready state")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("start calls = %d, want 2", got)
	}
}

func TestRunForwardWithRetryStopsDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		runForwardWithRetry(ctx, "local", "127.0.0.1:1234", func() error {
			calls.Add(1)
			return errors.New("listen on 127.0.0.1:1234: address already in use")
		}, nil)
		close(done)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forward retry did not stop after cancellation")
	}
}
