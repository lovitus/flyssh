//go:build windows

package moshsession

import (
	"os"

	"golang.org/x/sys/windows"
)

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
		_ = windows.SetConsoleMode(handle, mode)
	}
}
