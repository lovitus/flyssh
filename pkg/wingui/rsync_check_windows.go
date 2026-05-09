//go:build windows

package wingui

import (
	"os"
	"os/exec"
)

// resolveRsyncBinary returns the path to a usable rsync binary on Windows,
// checking %PATH% first then well-known installation directories.
func resolveRsyncBinary() (string, error) {
	if p, err := exec.LookPath("rsync"); err == nil {
		return p, nil
	}
	candidates := []string{
		`C:\msys64\usr\bin\rsync.exe`,
		`C:\msys32\usr\bin\rsync.exe`,
		`C:\cygwin64\bin\rsync.exe`,
		`C:\cygwin\bin\rsync.exe`,
		`C:\Program Files\cwRsync\bin\rsync.exe`,
		`C:\Program Files (x86)\cwRsync\bin\rsync.exe`,
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", exec.ErrNotFound
}
