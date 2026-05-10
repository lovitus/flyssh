package main

import (
	"io"
	"sync"
	"syscall"
	"unsafe"
)

var (
	modkernel32         = syscall.NewLazyDLL("kernel32.dll")
	procCreateEventW    = modkernel32.NewProc("CreateEventW")
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
func rawStdinReader() io.Reader {
	h := syscall.Stdin
	event, _, _ := procCreateEventW.Call(0, 1, 0, 0) // manual-reset, non-signaled
	return &overlappedReader{
		handle: h,
		event:  syscall.Handle(event),
	}
}

type overlappedReader struct {
	handle syscall.Handle
	event  syscall.Handle
	mu     sync.Mutex
}

type overlapped struct {
	Internal     uintptr
	InternalHigh uintptr
	Offset       uint32
	OffsetHigh   uint32
	HEvent       syscall.Handle
}

func (r *overlappedReader) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	ol := &overlapped{HEvent: r.event}
	var n uint32

	err := syscall.ReadFile(r.handle, buf, &n, (*syscall.Overlapped)(unsafe.Pointer(ol)))
	if err != nil {
		if err == syscall.ERROR_IO_PENDING {
			// Wait for the async read to complete
			ret, _, err2 := procGetOverlappedResult.Call(
				uintptr(r.handle),
				uintptr(unsafe.Pointer(ol)),
				uintptr(unsafe.Pointer(&n)),
				1, // bWait = TRUE
			)
			if ret == 0 {
				if n > 0 {
					return int(n), nil
				}
				return 0, err2
			}
		} else {
			if n > 0 {
				return int(n), nil
			}
			return 0, io.EOF
		}
	}
	if n == 0 {
		return 0, io.EOF
	}
	return int(n), nil
}
