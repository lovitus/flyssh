package auth

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

func TestPromptConsoleHelperProcess(t *testing.T) {
	if os.Args[len(os.Args)-1] != "flyssh-prompt-console-helper" {
		return
	}
	probe, err := openPromptTTY()
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	var original uint32
	if err := windows.GetConsoleMode(windows.Handle(probe.Fd()), &original); err != nil {
		t.Fatal(err)
	}
	for _, password := range []bool{false, true} {
		for _, pending := range []bool{false, true} {
			file, err := openPromptTTY()
			if err != nil {
				t.Fatal(err)
			}
			cancel := make(chan struct{})
			entered := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				_, err := readCancelablePromptTTY(file, cancel, func() (string, error) {
					close(entered)
					if password {
						p, err := term.ReadPassword(int(file.Fd()))
						return string(p), err
					}
					return bufio.NewReader(file).ReadString('\n')
				})
				done <- err
			}()
			<-entered
			if pending {
				select {
				case err := <-done:
					t.Fatalf("console read unexpectedly completed: %v", err)
				case <-time.After(30 * time.Millisecond):
				}
			}
			close(cancel)
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled console read succeeded")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("native console read not cancelled")
			}
			var after uint32
			if err := windows.GetConsoleMode(windows.Handle(probe.Fd()), &after); err != nil {
				t.Fatal(err)
			}
			if after != original {
				t.Fatalf("console mode not restored: before=%x after=%x", original, after)
			}
		}
	}
}

func TestPromptCancellationFailureRetainsOnlyOneNativeReader(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	cancel := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := readPromptTTYWithCancel(file, cancel, func() (string, error) { close(entered); <-release; return "", nil }, func(windows.Handle) error { return windows.ERROR_ACCESS_DENIED })
		done <- err
	}()
	defer func() {
		close(release)
		select {
		case promptTTYSlot <- struct{}{}:
			<-promptTTYSlot
		case <-time.After(2 * time.Second):
			t.Error("native worker did not release its slot")
		}
	}()
	brokerTestWait(t, entered)
	close(cancel)
	select {
	case err := <-done:
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Fatalf("cancellation error lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("unrecoverable cancellation error spun indefinitely")
	}
	other, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	_, err = readPromptTTYWithCancel(other, cancel, func() (string, error) {
		t.Error("started another native reader after cancellation failure")
		return "", nil
	}, func(windows.Handle) error { return nil })
	if err == nil {
		t.Fatal("cancelled queued native reader succeeded")
	}
}

func TestPromptConsoleCancellationAndPasswordModeRestoration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPromptConsoleHelperProcess$", "--", "flyssh-prompt-console-helper")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE, HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("real console cancellation: %v\n%s", err, out)
	}
}
