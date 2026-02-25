//go:build windows

package session

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVTProcessing enables ENABLE_VIRTUAL_TERMINAL_PROCESSING on stdout
// so ANSI escape sequences (colors, cursor movement, etc.) are interpreted
// correctly by the Windows console. Returns a function to restore the
// original mode.
func enableVTProcessing() func() {
	handle := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return func() {}
	}

	newMode := mode | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	if err := windows.SetConsoleMode(handle, newMode); err != nil {
		return func() {}
	}

	return func() {
		windows.SetConsoleMode(handle, mode)
	}
}
