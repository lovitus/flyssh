package auth

import (
	"errors"
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
// and cannot cancel it. Cancellation must stop before restoring the console:
// CancelSynchronousIo can also interrupt ReadPassword's deferred SetConsoleMode.
func readCancelablePromptTTY(file *os.File, cancel <-chan struct{}, read func() (string, error)) (string, error) {
	return readPromptTTYWithCancel(file, cancel, read, func(thread windows.Handle) error {
		ret, _, err := cancelPromptSynchronousIO.Call(uintptr(thread))
		if ret == 0 {
			return err
		}
		return nil
	}, func() (func() error, error) {
		var original uint32
		if err := windows.GetConsoleMode(windows.Handle(file.Fd()), &original); err != nil {
			return nil, fmt.Errorf("get prompt console mode: %w", err)
		}
		return func() error {
			if err := windows.SetConsoleMode(windows.Handle(file.Fd()), original); err != nil {
				return fmt.Errorf("restore prompt console mode: %w", err)
			}
			return nil
		}, nil
	})
}

// prepare runs under the global slot, before the native thread is published to
// the canceller. Its cleanup runs after read returns AND cancellation stops.
// Nil prepare supports readers with no console state (including test stand-ins).
func readPromptTTYWithCancel(file *os.File, cancel <-chan struct{}, read func() (string, error), cancelThread func(windows.Handle) error, prepare func() (func() error, error)) (string, error) {
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
	var restore func() error
	if prepare != nil {
		var err error
		restore, err = prepare()
		if err != nil {
			_ = file.Close()
			<-promptTTYSlot
			return "", err
		}
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
	readDone := make(chan struct{})
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
		close(readDone)
		// The canceller may still be in CancelSynchronousIo. Keep this thread
		// pinned and do not issue restoration I/O until it acknowledges stop.
		<-release
		if restore != nil {
			err = errors.Join(err, restore())
		}
		_ = file.Close()
		done <- readResult{value, err}
	}()
	ready := <-setup
	if ready.err != nil {
		return "", fmt.Errorf("open prompt reader thread: %w", ready.err)
	}
	defer windows.CloseHandle(ready.thread)
	released := false
	stopCancellation := func() {
		if !released {
			close(release)
			released = true
		}
	}
	defer stopCancellation()
	finish := func(cancelled bool) (string, error) {
		stopCancellation()
		result := <-done // Includes the explicit, checked mode restoration.
		if cancelled {
			return "", errors.Join(fmt.Errorf("prompt cancelled"), result.err)
		}
		return result.value, result.err
	}
	select {
	case <-readDone:
		return finish(false)
	case <-cancel:
	}
	// Cancellation may arrive just before the native read is submitted. Retry
	// ERROR_NOT_FOUND rather than losing that race and waiting indefinitely.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-readDone:
			return finish(true)
		default:
		}
		if err := cancelThread(ready.thread); err != nil && err != windows.ERROR_NOT_FOUND {
			// Do not spin forever on an unsupported/denied cancellation. The
			// worker still owns the file, restores its mode when read returns,
			// and keeps the global slot so this failure cannot leak per prompt.
			return "", fmt.Errorf("cancel console input (native reader retained until completion): %w", err)
		}
		select {
		case <-readDone:
			return finish(true)
		case <-ticker.C:
		}
	}
}
