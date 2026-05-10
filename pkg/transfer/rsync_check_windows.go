//go:build windows

package transfer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// resolveRsyncBinary returns the path to a usable rsync binary on Windows.
//
// Search order:
//  1. Same directory as the flyssh executable
//  2. Current working directory
//  3. %PATH% (covers Scoop, Chocolatey, manual installs)
//  4. Well-known MSYS2 / Cygwin / cwRsync / ICW installation paths
//
// If not found, actionable installation instructions are printed to stderr.
func resolveRsyncBinary() (string, error) {
	// 1. Same directory as flyssh executable
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "rsync.exe")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	// 2. Current working directory
	if cwd, err := os.Getwd(); err == nil {
		p := filepath.Join(cwd, "rsync.exe")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	// 3. %PATH%
	if p, err := exec.LookPath("rsync"); err == nil {
		return p, nil
	}

	// 4. Well-known fixed installation paths.
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

	fmt.Fprint(os.Stderr, rsyncNotFoundMessage)
	return "", fmt.Errorf("rsync not found")
}

const rsyncNotFoundMessage = `flyssh: rsync not found on this system.

To use rsync on Windows, install it using one of the following methods:

  Option 1 — Place rsync.exe next to flyssh.exe (simplest):
    Download from https://repo.msys2.org/msys/x86_64/ (search rsync)
    or from MSYS2/Cygwin, then copy rsync.exe and its DLLs into the
    same folder as flyssh.exe.

  Option 2 — Scoop (no admin required):
    scoop install rsync

  Option 3 — MSYS2:
    pacman -S rsync

  Option 4 — Cygwin:
    Install rsync from the Cygwin installer.

  Option 5 — cwRsync / ICW:
    https://itefix.net/cwrsync

After installing, restart your terminal and retry.
`
