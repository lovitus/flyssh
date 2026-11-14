package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestOverlappedReaderInvalidHandle(t *testing.T) {
	r, err := newOverlappedReader(syscall.InvalidHandle)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_, err = r.Read(make([]byte, 32))
	if !errors.Is(err, syscall.Errno(6)) {
		t.Fatalf("invalid handle became %v", err)
	}
}

func TestOverlappedResultKeepsBytesAndClassifiesErrors(t *testing.T) {
	for _, tc := range []struct {
		n         uint32
		err, want error
	}{
		{0, syscall.ERROR_BROKEN_PIPE, io.EOF},
		{0, syscall.ERROR_HANDLE_EOF, io.EOF},
		{0, nil, io.EOF},
		{3, syscall.ERROR_OPERATION_ABORTED, syscall.ERROR_OPERATION_ABORTED},
		{3, syscall.Errno(6), syscall.Errno(6)},
		{3, nil, nil},
	} {
		n, err := overlappedReadResult(tc.n, tc.err)
		if n != int(tc.n) || !errors.Is(err, tc.want) {
			t.Fatalf("(%d,%v) -> (%d,%v), want %v", tc.n, tc.err, n, err, tc.want)
		}
	}
}

func TestOverlappedReaderPendingPipe(t *testing.T) {
	for _, mode := range []string{"data", "eof", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			name, err := windows.UTF16PtrFromString(fmt.Sprintf(`\\.\pipe\flyssh-read-test-%d-%d`, os.Getpid(), time.Now().UnixNano()))
			if err != nil {
				t.Fatal(err)
			}
			server, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_INBOUND|windows.FILE_FLAG_OVERLAPPED,
				windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT, 1, 4096, 4096, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(server)
			client, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if client != 0 {
					windows.CloseHandle(client)
				}
			}()
			// The client connected before ConnectNamedPipe, so this must not wait.
			if err := windows.ConnectNamedPipe(server, nil); err != nil && err != windows.ERROR_PIPE_CONNECTED {
				t.Fatal(err)
			}
			r, err := newOverlappedReader(syscall.Handle(server))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			type result struct {
				text string
				err  error
			}
			done := make(chan result, 1)
			buf := make([]byte, 32)
			ol := &syscall.Overlapped{HEvent: r.event}
			var count uint32
			if err := syscall.ReadFile(syscall.Handle(server), buf, &count, ol); err != syscall.ERROR_IO_PENDING {
				t.Fatalf("expected a genuinely pending native read, got %v", err)
			}
			go func() {
				err := waitPendingStdinRead(syscall.Handle(server), ol, &count)
				n, err := overlappedReadResult(count, err)
				done <- result{string(buf[:n]), err}
			}()
			if mode == "eof" {
				windows.CloseHandle(client)
				client = 0
			} else if mode == "cancel" {
				if err := windows.CancelIoEx(server, nil); err != nil {
					t.Fatal(err)
				}
			} else {
				var n uint32
				if err := windows.WriteFile(client, []byte("rsync-data"), &n, nil); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case got := <-done:
				if mode == "cancel" {
					if got.text != "" || !errors.Is(got.err, syscall.ERROR_OPERATION_ABORTED) {
						t.Fatalf("pending cancellation: %+v", got)
					}
				} else if mode == "eof" {
					if got.text != "" || got.err != io.EOF {
						t.Fatalf("pending EOF: %+v", got)
					}
				} else if got.text != "rsync-data" || got.err != nil {
					t.Fatalf("pending data: %+v", got)
				}
			case <-time.After(2 * time.Second):
				// Unblock the native pending operation before deferred reader Close.
				_ = windows.CancelIoEx(server, nil)
				<-done
				t.Fatal("pending read did not complete")
			}
		})
	}
}
