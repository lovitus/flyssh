package main

import (
	"io"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

var (
	modkernel32             = syscall.NewLazyDLL("kernel32.dll")
	procCreateEventW        = modkernel32.NewProc("CreateEventW")
	procGetOverlappedResult = modkernel32.NewProc("GetOverlappedResult")
)

// rawStdinReader returns an io.Reader that reads from the Windows stdin
// handle using overlapped (async) I/O.
//
// When a native Go process is forked by MSYS2/Cygwin/cwRsync as an rsync
// transport, the inherited stdin pipe is opened for overlapped I/O.  Go's
// os.Stdin.Read fails because it calls ReadFile with a nil OVERLAPPED
// pointer, which is invalid for async handles (Windows error 87).
//
// This reader uses a proper OVERLAPPED struct so ReadFile succeeds.
func rawStdinReader() (io.ReadCloser, error) {
	return newOverlappedReader(syscall.Stdin)
}

func newOverlappedReader(handle syscall.Handle) (*overlappedReader, error) {
	event, _, err := procCreateEventW.Call(0, 1, 0, 0) // manual-reset, non-signaled
	if event == 0 {
		return nil, err
	}
	return &overlappedReader{handle: handle, event: syscall.Handle(event)}, nil
}

// Close releases only our event, after the copying goroutine has finished Read.
// It is not a cancellation API: a pending inherited stdin read lives until the
// one-shot transport process exits if the remote command finishes first.
func (r *overlappedReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.event == 0 {
		return nil
	}
	err := syscall.CloseHandle(r.event)
	r.event = 0
	return err
}

type overlappedReader struct {
	handle syscall.Handle
	event  syscall.Handle
	mu     sync.Mutex
}

func (r *overlappedReader) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	ol := &syscall.Overlapped{HEvent: r.event}
	var n uint32

	err := syscall.ReadFile(r.handle, buf, &n, ol)
	if err == syscall.ERROR_IO_PENDING {
		err = waitPendingStdinRead(r.handle, ol, &n)
	}
	runtime.KeepAlive(buf)
	runtime.KeepAlive(ol)
	return overlappedReadResult(n, err)
}

// The caller retains the read buffer and OVERLAPPED until this returns.
func waitPendingStdinRead(handle syscall.Handle, ol *syscall.Overlapped, n *uint32) error {
	ret, _, err := procGetOverlappedResult.Call(
		uintptr(handle), uintptr(unsafe.Pointer(ol)), uintptr(unsafe.Pointer(n)), 1,
	)
	if ret == 0 {
		return err
	}
	return nil
}

func overlappedReadResult(n uint32, err error) (int, error) {
	if err == syscall.ERROR_BROKEN_PIPE || err == syscall.ERROR_HANDLE_EOF || (err == nil && n == 0) {
		err = io.EOF
	}
	// io.Copy consumes n bytes before reporting err; do not discard either.
	return int(n), err
}
