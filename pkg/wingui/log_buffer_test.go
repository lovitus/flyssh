package wingui

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

type gatedLogWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *gatedLogWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}

type failedLogWriter struct{ short bool }

func (w failedLogWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, errors.New("terminal gone")
}

func waitLogWorker(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("log worker did not finish")
	}
}
func TestBestEffortWriterBoundsBlockedTerminal(t *testing.T) {
	out := &gatedLogWriter{entered: make(chan struct{}), release: make(chan struct{})}
	w := newBestEffortWriter(out, 1024)
	defer func() { close(out.release); w.Close(); waitLogWorker(t, w.done) }()
	_, _ = w.Write([]byte("start"))
	waitLogWorker(t, out.entered)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			_, _ = w.Write([]byte(strings.Repeat("x", 128)))
		}
		close(done)
	}()
	waitLogWorker(t, done)
	w.mu.Lock()
	pending, dropped := w.pending, w.dropped
	w.mu.Unlock()
	if pending > 1024 || dropped == 0 {
		t.Fatalf("unbounded/missing drop: pending=%d dropped=%d", pending, dropped)
	}
}
func TestBestEffortWriterDisablesFailedOrShortSink(t *testing.T) {
	for _, short := range []bool{false, true} {
		w := newBestEffortWriter(failedLogWriter{short: short}, 1024)
		_, _ = w.Write([]byte("hello"))
		waitLogWorker(t, w.done)
		_, _ = w.Write([]byte("again"))
		w.Close()
		w.mu.Lock()
		failed, pending, dropped := w.failed, w.pending, w.dropped
		w.mu.Unlock()
		if !failed || pending != 0 || dropped == 0 {
			t.Fatalf("failed sink retained records: failed=%v pending=%d dropped=%d", failed, pending, dropped)
		}
	}
}
func TestPendingLogBatchesBoundsClearsAndCloses(t *testing.T) {
	var log pendingLog
	callbacks := 0
	for i := 0; i < 1000; i++ {
		log.append(strings.Repeat("界", 100), func() { callbacks++ })
	}
	if callbacks != 1 {
		t.Fatalf("posted %d callbacks", callbacks)
	}
	text := log.take()
	if len(text) > guiPendingLogBytes || !utf8.ValidString(text) || !strings.Contains(text, "omitted") {
		t.Fatalf("invalid bounded text: %d bytes", len(text))
	}
	log.append("old", func() { callbacks++ })
	log.clear(false)
	if got := log.take(); got != "" {
		t.Fatalf("clear restored stale text: %q", got)
	}
	log.clear(true)
	log.clear(false) // Clearing stale UI state must never reopen a closed queue.
	log.append("closed", func() { t.Error("posted after closing") })
	if got := log.take(); got != "" {
		t.Fatalf("closed queue retained %q", got)
	}
}
