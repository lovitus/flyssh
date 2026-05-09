//go:build windows

package transfer

import (
	"fmt"
	"os"
	"os/exec"
)

// resolveRsyncBinary returns the path to a usable rsync binary on Windows.
// It checks %PATH% first, then well-known installation directories for
// MSYS2, Cygwin, and cwRsync. If none are found it prints installation
// instructions to stderr and returns an error.
func resolveRsyncBinary() (string, error) {
	// 1. Prefer whatever is already in %PATH% (covers Scoop shims, etc.)
	if p, err := exec.LookPath("rsync"); err == nil {
		return p, nil
	}

	// 2. Well-known fixed installation paths, checked in priority order.
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

	// Not found anywhere — print actionable instructions before returning.
	fmt.Fprint(os.Stderr, rsyncNotFoundMessage)
	return "", fmt.Errorf("rsync not found")
}

const rsyncNotFoundMessage = `flyssh: rsync not found on this system.

To install rsync on Windows, use one of the following options:

  Scoop (no admin required — recommended):
    scoop install rsync

  Chocolatey:
    choco install rsync

  MSYS2:
    pacman -S rsync
    (flyssh will find it automatically at the default install path)

  cwRsync (manual download):
    https://itefix.net/cwrsync
    Install to the default path and flyssh will find it automatically.

After installing via Scoop or Chocolatey, restart your terminal and retry.
`
