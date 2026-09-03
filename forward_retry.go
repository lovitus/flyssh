package main

import (
	"context"
	"errors"
	"log"
	"net"
	"strings"
	"time"
)

const (
	forwardRetryInitialDelay = 250 * time.Millisecond
	forwardRetryMaxDelay     = 5 * time.Second
)

// runForwardWithRetry keeps transient local listener failures out of the
// session lifecycle. The interactive shell can continue while a listener is
// being rebound after a previous run released its port.
func runForwardWithRetry(ctx context.Context, kind, spec string, start func() error, errCh chan<- error) {
	delay := forwardRetryInitialDelay
	attempt := 0
	for {
		if ctx.Err() != nil {
			return
		}

		err := start()
		if err == nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
		if !retryableForwardError(kind, err) {
			reportForwardError(errCh, kind, spec, err)
			return
		}

		attempt++
		// Avoid filling the terminal with the same bind error while still
		// leaving an occasional breadcrumb that recovery is in progress.
		if attempt == 1 || attempt%12 == 0 {
			log.Printf("flyssh: %s forward unavailable (%s): %v; retrying in %s", kind, spec, err, delay)
		}
		if !waitForwardRetry(ctx, delay) {
			return
		}
		if delay < forwardRetryMaxDelay {
			delay *= 2
			if delay > forwardRetryMaxDelay {
				delay = forwardRetryMaxDelay
			}
		}
	}
}

func retryableForwardError(kind string, err error) bool {
	if err == nil || (kind != "local" && kind != "dynamic") {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return false
	}

	message := strings.ToLower(err.Error())
	if strings.Contains(message, "use of closed network connection") ||
		strings.Contains(message, "invalid "+kind+" forward spec") {
		return false
	}
	return strings.Contains(message, "listen") || strings.Contains(message, "bind")
}

func waitForwardRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
