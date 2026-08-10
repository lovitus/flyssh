//go:build windows

package wingui

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDiscoverShellClientsPrefersFlySSHDirectory(t *testing.T) {
	dir := t.TempDir()
	flysshExe := filepath.Join(dir, "flyssh.exe")
	for _, name := range []string{"putty.exe", "Xshell.exe", "SecureCRT.exe"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("stub"), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	clients := discoverShellClients(flysshExe)
	for kind, name := range map[shellClientKind]string{
		shellClientPuTTY:     "putty.exe",
		shellClientXshell:    "Xshell.exe",
		shellClientSecureCRT: "SecureCRT.exe",
	} {
		want := filepath.Join(dir, name)
		if clients[kind] != want {
			t.Fatalf("%s path = %q, want %q", kind, clients[kind], want)
		}
	}
}

func TestShellClientExecutableName(t *testing.T) {
	if got := shellClientExecutableName(shellClientPuTTY); got != "putty.exe" {
		t.Fatalf("PuTTY executable = %q", got)
	}
	if got := shellClientExecutableName("unknown"); got != "" {
		t.Fatalf("unknown executable = %q", got)
	}
}

func TestValidateShellClientExecutable(t *testing.T) {
	dir := t.TempDir()
	putty := filepath.Join(dir, "PUTTY.EXE")
	if err := os.WriteFile(putty, []byte("stub"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := validateShellClientExecutable(shellClientPuTTY, putty)
	if err != nil {
		t.Fatalf("validate PuTTY: %v", err)
	}
	if got != putty {
		t.Fatalf("validated path = %q, want %q", got, putty)
	}

	wrong := filepath.Join(dir, "other.exe")
	if err := os.WriteFile(wrong, []byte("stub"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateShellClientExecutable(shellClientPuTTY, wrong); err == nil {
		t.Fatal("expected mismatched executable name to be rejected")
	}
	if _, err := validateShellClientExecutable(shellClientPuTTY, filepath.Join(dir, "missing.exe")); err == nil {
		t.Fatal("expected missing executable to be rejected")
	}
}

func TestMissingShellClientToolTipOffersLocator(t *testing.T) {
	got := shellClientToolTip(shellClientXshell, "")
	if !strings.Contains(got, "click to locate") {
		t.Fatalf("missing-client tooltip = %q", got)
	}
}

func TestXshellPatternsIncludeXmanagerEnterpriseBundle(t *testing.T) {
	t.Setenv("ProgramFiles", "")
	t.Setenv("ProgramFiles(x86)", `C:\Program Files (x86)`)
	t.Setenv("LOCALAPPDATA", "")
	patterns := standardShellClientPatterns(shellClientXshell)
	want := `C:\Program Files (x86)\NetSarang\Xmanager Enterprise *\Xshell.exe`
	if !slices.Contains(patterns, want) {
		t.Fatalf("Xshell patterns %#v do not include %q", patterns, want)
	}
}

func TestDiscoveredShellClientPathsExist(t *testing.T) {
	clients := discoverShellClients("")
	for kind, executable := range clients {
		info, err := os.Stat(executable)
		if err != nil {
			t.Fatalf("discovered %s path %q: %v", kind, executable, err)
		}
		if info.IsDir() {
			t.Fatalf("discovered %s path is a directory: %q", kind, executable)
		}
		t.Logf("discovered %s at %s", kind, executable)
	}
}
