package wingui

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestGUIOutputHelperProcess(t *testing.T) {
	if os.Args[len(os.Args)-1] == "flyssh-held-pipe-helper" {
		parent, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, uint32(os.Getppid()))
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(parent)
		var held windows.Handle
		if err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(os.Stdout.Fd()), parent, &held, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(os.Stdout, "%d\n", held)
		os.Exit(0)
	}
	if os.Args[len(os.Args)-1] == "flyssh-wait-helper" {
		for {
			time.Sleep(time.Hour)
		}
	}
	if os.Args[len(os.Args)-1] != "flyssh-output-helper" {
		return
	}
	chunk := bytes.Repeat([]byte("x"), 32*1024)
	for i := 0; i < 64; i++ {
		_, _ = os.Stdout.Write(chunk)
		_, _ = os.Stderr.Write(chunk)
	}
	_, _ = os.Stdout.Write([]byte("\nlast-hash-result\n"))
	os.Exit(0)
}

func TestRunChildDrainsDespiteBlockedTerminalAndKeepsCapture(t *testing.T) {
	_ = terminalMirror(os.Stdout)
	oldOut, oldErr := terminalStdout, terminalStderr
	out := &gatedLogWriter{entered: make(chan struct{}), release: make(chan struct{})}
	errOut := &gatedLogWriter{entered: make(chan struct{}), release: make(chan struct{})}
	terminalStdout = newBestEffortWriter(out, 4096)
	terminalStderr = newBestEffortWriter(errOut, 4096)
	// A small initial record occupies each writer; the larger output chunks
	// that follow are intentionally dropped rather than blocking the pipe drain.
	_, _ = terminalStdout.Write([]byte("block"))
	_, _ = terminalStderr.Write([]byte("block"))
	waitLogWorker(t, out.entered)
	waitLogWorker(t, errOut.entered)
	defer func() {
		close(out.release)
		close(errOut.release)
		terminalStdout.Close()
		terminalStderr.Close()
		waitLogWorker(t, terminalStdout.done)
		waitLogWorker(t, terminalStderr.done)
		terminalStdout, terminalStderr = oldOut, oldErr
	}()
	for _, capture := range []bool{false, true} {
		a := &app{exe: os.Args[0]}
		type result struct {
			data []byte
			code int
			err  error
		}
		done := make(chan result, 1)
		go func() {
			data, code, err := a.runChild([]string{"-test.run=^TestGUIOutputHelperProcess$", "--", "flyssh-output-helper"}, capture)
			done <- result{data, code, err}
		}()
		select {
		case got := <-done:
			if got.err != nil || got.code != 0 {
				t.Fatalf("child failed: code=%d err=%v", got.code, got.err)
			}
			if capture && (len(got.data) != 64*32*1024+len("\nlast-hash-result\n") || !strings.HasSuffix(string(got.data), "\nlast-hash-result\n")) {
				t.Fatalf("capture truncated: %d", len(got.data))
			}
		case <-time.After(45 * time.Second):
			a.killCurrent()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
			t.Fatal("blocked terminal stopped child drain")
		}
		if len(a.logPending.take()) > guiPendingLogBytes {
			t.Fatal("GUI pending log exceeded bound")
		}
	}
}

func TestRunChildBoundsPipeHeldAfterExitAndPreservesExitStatus(t *testing.T) {
	a := &app{exe: os.Args[0]}
	type result struct {
		data []byte
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, code, err := a.runChild([]string{"-test.run=^TestGUIOutputHelperProcess$", "--", "flyssh-held-pipe-helper"}, true)
		done <- result{data, code, err}
	}()
	select {
	case got := <-done:
		// The child duplicates its stdout writer into this parent process. It
		// survives Job close exactly like a handle held by an escaped descendant.
		held, err := strconv.ParseUint(strings.TrimSpace(string(got.data)), 10, 64)
		if err != nil {
			t.Fatalf("missing held handle: code=%d err=%v output=%q", got.code, got.err, got.data)
		}
		defer windows.CloseHandle(windows.Handle(held))
		if got.code != 0 || !errors.Is(got.err, os.ErrClosed) {
			t.Fatalf("exit or pipe failure lost: code=%d err=%v", got.code, got.err)
		}
	case <-time.After(45 * time.Second):
		a.killCurrent()
		t.Fatal("held write handle prevented child cleanup")
	}
}

func TestPublishChildKillsAlreadyCancelledOperation(t *testing.T) {
	child, _, _, err := startChild(os.Args[0], []string{"-test.run=^TestGUIOutputHelperProcess$", "--", "flyssh-wait-helper"})
	if err != nil {
		t.Fatal(err)
	}
	defer child.closePipes()
	a := &app{operationCanceled: true}
	a.publishChild(child)
	done := make(chan error, 1)
	go func() { done <- child.wait() }()
	select {
	case <-done:
		// Closing a kill-on-close Windows Job may report exit status zero;
		// bounded process termination is the cancellation contract.
	case <-time.After(5 * time.Second):
		child.kill()
		t.Fatal("cancelled child survived publication")
	}
	if a.current != nil {
		t.Fatal("cancelled child was published")
	}
}

func TestRunChildHonorsCancellationBeforePublication(t *testing.T) {
	a := &app{exe: os.Args[0], operationCanceled: true}
	done := make(chan struct{})
	go func() {
		_, _, _ = a.runChild([]string{"-test.run=^TestGUIOutputHelperProcess$", "--", "flyssh-output-helper"}, true)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		a.killCurrent()
		t.Fatal("cancelled publication did not finish")
	}
	a.mu.Lock()
	current := a.current
	a.mu.Unlock()
	if current != nil {
		t.Fatal("cancelled child remained published")
	}
}
