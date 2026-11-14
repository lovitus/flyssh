package auth

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Model ReadPassword's ignored deferred SetConsoleMode failure: the callback
// returns an error with echo/line input still disabled on an actual console.
// The cancellation owner must independently restore the captured initial mode.
func TestPromptConsoleRestoresModeAfterReadError(t *testing.T) {
	const helper = "flyssh-prompt-interrupted-restore-helper"
	if os.Args[len(os.Args)-1] != helper {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPromptConsoleRestoresModeAfterReadError$", "-test.v", "-test.timeout=8s", "--", helper)
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE, HideWindow: true}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("interrupted password restoration: %v (context: %v)\n%s", err, ctx.Err(), out)
		}
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
	const passwordFlags = windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT
	if original&passwordFlags != passwordFlags {
		t.Fatalf("fixture console must start with echo and line input enabled: %x", original)
	}
	file, err := openPromptTTY()
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	_, err = readCancelablePromptTTY(file, make(chan struct{}), func() (string, error) {
		mode := original &^ passwordFlags
		if err := windows.SetConsoleMode(windows.Handle(file.Fd()), mode); err != nil {
			return "", err
		}
		changed = true
		return "", windows.ERROR_OPERATION_ABORTED
	})
	if !changed || !errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
		t.Fatalf("expected mode-changing read to return ERROR_OPERATION_ABORTED: changed=%v err=%v", changed, err)
	}
	var after uint32
	if err := windows.GetConsoleMode(windows.Handle(probe.Fd()), &after); err != nil {
		t.Fatal(err)
	}
	if after != original {
		t.Fatalf("console mode not restored: before=%x after=%x", original, after)
	}
}
