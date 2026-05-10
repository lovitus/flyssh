//go:build windows

package wingui

import (
	"os"
	"os/exec"
	"path/filepath"
)

// resolveRsyncBinary returns the path to a usable rsync binary on Windows.
// Search order matches the transfer package: exe dir, cwd, PATH, well-known paths.
func resolveRsyncBinary() (string, error) {
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "rsync.exe")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		p := filepath.Join(cwd, "rsync.exe")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
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
		`C:\Program Files (x86)\ICW\bin\rsync.exe`,
		`C:\Program Files\ICW\bin\rsync.exe`,
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", exec.ErrNotFound
}
