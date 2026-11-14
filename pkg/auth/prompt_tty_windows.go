package auth

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/windows"
)

var cancelPromptSynchronousIO = windows.NewLazySystemDLL("kernel32.dll").NewProc("CancelSynchronousIo")

// Also serialize across broker instances. If the OS rejects cancellation, the
// one outstanding native reader keeps this slot until it actually returns;
// later cancelled prompts must not accumulate more native readers/threads.
var promptTTYSlot = make(chan struct{}, 1)

// Console reads are synchronous. os.File.Close waits for the read's reference
// and cannot cancel it. CancelSynchronousIo must target the exact native thread
// issuing ReadConsole/ReadFile, including ReadPassword's mode restoration.
func readCancelablePromptTTY(file *os.File, cancel <-chan struct{}, read func() (string, error)) (string, error) {
	return readPromptTTYWithCancel(file, cancel, read, func(thread windows.Handle) error {
		ret, _, err := cancelPromptSynchronousIO.Call(uintptr(thread))
		if ret == 0 {
			return err
		}
		return nil
	})
}

func readPromptTTYWithCancel(file *os.File, cancel <-chan struct{}, read func() (string, error), cancelThread func(windows.Handle) error) (string, error) {
	if err := cancelPromptSynchronousIO.Find(); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("find console cancellation API: %w", err)
	}
	select {
	case promptTTYSlot <- struct{}{}:
	case <-cancel:
		_ = file.Close()
		return "", fmt.Errorf("prompt cancelled")
	}
	type setupResult struct {
		thread windows.Handle
		err    error
	}
	type readResult struct {
		value string
		err   error
	}
	setup := make(chan setupResult, 1)
	done := make(chan readResult, 1)
	release := make(chan struct{})
	go func() {
		defer func() { <-promptTTYSlot }()
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		thread, err := windows.OpenThread(windows.THREAD_TERMINATE, false, windows.GetCurrentThreadId())
		setup <- setupResult{thread, err}
		if err != nil {
			_ = file.Close()
			return
		}
		value, err := read()
		_ = file.Close() // The actual native read and mode restoration have finished.
		done <- readResult{value, err}
		// Do not let the runtime reuse this thread until the canceller has stopped.
		<-release
	}()
	ready := <-setup
	if ready.err != nil {
		return "", fmt.Errorf("open prompt reader thread: %w", ready.err)
	}
	defer windows.CloseHandle(ready.thread)
	defer close(release)
	select {
	case result := <-done:
		return result.value, result.err
	case <-cancel:
	}
	// Cancellation may arrive just before the native read is submitted. Retry
	// ERROR_NOT_FOUND rather than losing that race and waiting indefinitely.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return "", fmt.Errorf("prompt cancelled")
		default:
		}
		if err := cancelThread(ready.thread); err != nil && err != windows.ERROR_NOT_FOUND {
			// Do not spin forever on an unsupported/denied cancellation. The
			// worker still owns the file, restores its mode when read returns,
			// and keeps the global slot so this failure cannot leak per prompt.
			return "", fmt.Errorf("cancel console input (native reader retained until completion): %w", err)
		}
		select {
		case <-done:
			return "", fmt.Errorf("prompt cancelled")
		case <-ticker.C:
		}
	}
}
