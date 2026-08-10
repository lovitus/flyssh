//go:build windows

package wingui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func discoverShellClients(flysshExe string) map[shellClientKind]string {
	result := make(map[shellClientKind]string)
	for _, kind := range []shellClientKind{shellClientPuTTY, shellClientXshell, shellClientSecureCRT} {
		if executable := discoverShellClient(kind, flysshExe); executable != "" {
			result[kind] = executable
		}
	}
	return result
}

func discoverShellClient(kind shellClientKind, flysshExe string) string {
	exeName := shellClientExecutableName(kind)
	if exeName == "" {
		return ""
	}

	if flysshExe != "" {
		if candidate := existingFile(filepath.Join(filepath.Dir(flysshExe), exeName)); candidate != "" {
			return candidate
		}
	}
	if candidate := registryAppPath(exeName); candidate != "" {
		return candidate
	}
	if candidate, err := exec.LookPath(exeName); err == nil {
		if absolute, absErr := filepath.Abs(candidate); absErr == nil {
			candidate = absolute
		}
		return candidate
	}
	for _, pattern := range standardShellClientPatterns(kind) {
		matches, _ := filepath.Glob(pattern)
		for _, match := range matches {
			if candidate := existingFile(match); candidate != "" {
				return candidate
			}
		}
	}
	return ""
}

func shellClientExecutableName(kind shellClientKind) string {
	switch kind {
	case shellClientPuTTY:
		return "putty.exe"
	case shellClientXshell:
		return "Xshell.exe"
	case shellClientSecureCRT:
		return "SecureCRT.exe"
	default:
		return ""
	}
}

func shellClientToolTip(kind shellClientKind, executable string) string {
	if executable == "" {
		return shellClientName(kind) + " was not found; click to locate its executable"
	}
	return "Open " + shellClientName(kind) + "\r\n" + executable
}

func validateShellClientExecutable(kind shellClientKind, executable string) (string, error) {
	want := shellClientExecutableName(kind)
	if want == "" {
		return "", fmt.Errorf("unsupported shell client: %s", kind)
	}
	candidate := existingFile(executable)
	if candidate == "" {
		return "", fmt.Errorf("selected executable does not exist: %s", executable)
	}
	if !strings.EqualFold(filepath.Base(candidate), want) {
		return "", fmt.Errorf("select %s for %s", want, shellClientName(kind))
	}
	return candidate, nil
}

func registryAppPath(exeName string) string {
	keyPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\` + exeName
	for _, root := range []registry.Key{registry.CURRENT_USER, registry.LOCAL_MACHINE} {
		for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY, 0} {
			key, err := registry.OpenKey(root, keyPath, registry.QUERY_VALUE|view)
			if err != nil {
				continue
			}
			value, valueType, valueErr := key.GetStringValue("")
			_ = key.Close()
			if valueErr != nil {
				continue
			}
			if valueType == registry.EXPAND_SZ {
				if expanded, expandErr := registry.ExpandString(value); expandErr == nil {
					value = expanded
				}
			}
			value = strings.Trim(strings.TrimSpace(value), `"`)
			if candidate := existingFile(value); candidate != "" {
				return candidate
			}
		}
	}
	return ""
}

func standardShellClientPatterns(kind shellClientKind) []string {
	roots := []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LOCALAPPDATA")}
	patterns := make([]string, 0, len(roots)*2)
	for _, root := range roots {
		if root == "" {
			continue
		}
		switch kind {
		case shellClientPuTTY:
			patterns = append(patterns,
				filepath.Join(root, "PuTTY", "putty.exe"),
				filepath.Join(root, "Programs", "PuTTY", "putty.exe"),
			)
		case shellClientXshell:
			patterns = append(patterns,
				filepath.Join(root, "NetSarang", "Xshell *", "Xshell.exe"),
				filepath.Join(root, "NetSarang", "Xmanager Enterprise *", "Xshell.exe"),
				filepath.Join(root, "Programs", "NetSarang", "Xshell *", "Xshell.exe"),
			)
		case shellClientSecureCRT:
			patterns = append(patterns,
				filepath.Join(root, "VanDyke Software", "Clients", "SecureCRT.exe"),
				filepath.Join(root, "VanDyke Software", "SecureCRT", "SecureCRT.exe"),
			)
		}
	}
	return patterns
}

func existingFile(path string) string {
	if path == "" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return ""
	}
	absolute, err := filepath.Abs(path)
	if err == nil {
		return absolute
	}
	return path
}

func launchExternalShell(executable string, args []string) error {
	if executable == "" {
		return fmt.Errorf("shell client executable is empty")
	}
	cmd := exec.Command(executable, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
