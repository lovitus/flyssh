package auth

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"testing/synctest"
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
			var cancelErr error
			select {
			case err := <-done:
				cancelErr = err
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
				t.Fatalf("console mode not restored: before=%x after=%x password=%v pending=%v cancellation=%v", original, after, password, pending, cancelErr)
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
	restored := make(chan struct{})
	cancel := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := readPromptTTYWithCancel(file, cancel, func() (string, error) { close(entered); <-release; return "", nil }, func(windows.Handle) error { return windows.ERROR_ACCESS_DENIED }, func() (func() error, error) {
			return func() error { close(restored); return nil }, nil
		})
		done <- err
	}()
	defer func() {
		close(release)
		select {
		case promptTTYSlot <- struct{}{}:
			<-promptTTYSlot
			select {
			case <-restored:
			default:
				t.Error("retained reader released its slot before restoring state")
			}
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
	select {
	case <-restored:
		t.Fatal("restored state while failed cancellation left native read active")
	default:
	}
	other, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	_, err = readPromptTTYWithCancel(other, cancel, func() (string, error) {
		t.Error("started another native reader after cancellation failure")
		return "", nil
	}, func(windows.Handle) error { return nil }, nil)
	if err == nil {
		t.Fatal("cancelled queued native reader succeeded")
	}
}

func TestPromptRestorationFailureAfterNormalRead(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	restoreErr := errors.New("injected restoration failure")
	value, err := readPromptTTYWithCancel(file, make(chan struct{}), func() (string, error) {
		return "answer", nil
	}, func(windows.Handle) error { t.Error("unexpected cancellation"); return nil }, func() (func() error, error) {
		return func() error { return restoreErr }, nil
	})
	if value != "answer" || !errors.Is(err, restoreErr) {
		t.Fatalf("value=%q restoration error=%v", value, err)
	}
}

// Hold an in-flight cancellation past the end of read. Restoration must wait
// for that call to return, and the caller must then wait for restoration.
func TestPromptRestorationWaitsForCancellationToStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		file, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		cancel := make(chan struct{})
		readEntered, readRelease := make(chan struct{}), make(chan struct{})
		cancelEntered, cancelRelease := make(chan struct{}), make(chan struct{})
		restoreEntered, restoreRelease := make(chan struct{}), make(chan struct{})
		done := make(chan error, 1)
		restoreErr := errors.New("injected restoration failure")
		go func() {
			_, err := readPromptTTYWithCancel(file, cancel, func() (string, error) {
				close(readEntered)
				<-readRelease
				return "", windows.ERROR_OPERATION_ABORTED
			}, func(windows.Handle) error {
				close(cancelEntered)
				<-cancelRelease
				return nil
			}, func() (func() error, error) {
				return func() error {
					close(restoreEntered)
					<-restoreRelease
					return restoreErr
				}, nil
			})
			done <- err
		}()
		<-readEntered
		close(cancel)
		<-cancelEntered
		close(readRelease)
		synctest.Wait()
		select {
		case <-restoreEntered:
			t.Fatal("restoration overlapped in-flight native cancellation")
		default:
		}
		close(cancelRelease)
		<-restoreEntered
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("caller returned before restoration completed")
		default:
		}
		close(restoreRelease)
		if err := <-done; !errors.Is(err, restoreErr) {
			t.Fatalf("restoration error lost: %v", err)
		}
	})
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
