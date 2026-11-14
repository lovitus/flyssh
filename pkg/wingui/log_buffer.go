package wingui

import (
	"io"
	"strings"
	"sync"
	"unicode/utf8"
)

// bestEffortWriter owns one worker for the GUI lifetime. A stalled OS writer
// may occupy that worker until process exit, but cannot block a producer or
// create a new worker per transfer. Both the pending bytes and records are bounded.
type bestEffortWriter struct {
	mu      sync.Mutex
	queue   chan []byte
	pending int
	limit   int
	dropped uint64
	failed  bool
	closed  bool
	done    chan struct{}
}

func newBestEffortWriter(out io.Writer, limit int) *bestEffortWriter {
	w := &bestEffortWriter{queue: make(chan []byte, 128), limit: limit, done: make(chan struct{})}
	go func() {
		defer close(w.done)
		for p := range w.queue {
			n, err := out.Write(p)
			w.mu.Lock()
			w.pending -= len(p)
			if err != nil || n != len(p) {
				w.failed = true
				w.dropped += uint64(len(p) - n)
			}
			failed := w.failed
			w.mu.Unlock()
			if failed {
				// Release queued data; no more records will be enqueued.
				for {
					select {
					case p, ok := <-w.queue:
						if !ok {
							return
						}
						w.mu.Lock()
						w.pending -= len(p)
						w.dropped += uint64(len(p))
						w.mu.Unlock()
					default:
						return
					}
				}
			}
		}
	}()
	return w
}

func (w *bestEffortWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed || w.closed || len(p) > w.limit-w.pending {
		w.dropped += uint64(len(p))
		return len(p), nil
	}
	select {
	case w.queue <- append([]byte(nil), p...):
		w.pending += len(p)
	default:
		w.dropped += uint64(len(p))
	}
	return len(p), nil
}

func (w *bestEffortWriter) droppedBytes() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dropped
}

// Close stops accepting records. It never waits for a blocked terminal Write.
func (w *bestEffortWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed {
		w.closed = true
		close(w.queue)
	}
}

const guiPendingLogBytes = 64 * 1024
const guiRetainedLogBytes = 1024 * 1024

// pendingLog limits both queued text and the number of queued UI callbacks.
// Only the UI callback consumes text; no producer touches a native control.
type pendingLog struct {
	mu        sync.Mutex
	text      string
	scheduled bool
	closed    bool
}

func (l *pendingLog) append(text string, schedule func()) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.text = logTail(l.text+text, guiPendingLogBytes)
	post := !l.scheduled
	l.scheduled = true
	l.mu.Unlock()
	if post {
		schedule()
	}
}

func (l *pendingLog) take() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	text := l.text
	l.text = ""
	l.scheduled = false
	return text
}

func (l *pendingLog) clear(close bool) {
	l.mu.Lock()
	l.text = ""
	l.closed = l.closed || close
	l.mu.Unlock()
}

func logTail(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	const marker = "[older log output omitted]\r\n"
	text = text[len(text)-(limit-len(marker)):]
	for len(text) > 0 && !utf8.RuneStart(text[0]) {
		text = text[1:]
	}
	return marker + strings.Clone(text)
}
