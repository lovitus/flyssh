package wingui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const promptNotice = "Running; answer prompts in terminal if shown"

type remoteEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"`
}

func buildChildArgs(rawArgs []string, extra ...string) []string {
	args := make([]string, 0, len(rawArgs)+len(extra))
	for i := 0; i < len(rawArgs); i++ {
		arg := rawArgs[i]
		stripped, keep := stripChildRuntimeFlag(arg)
		if keep {
			args = append(args, stripped)
		}
		if optionConsumesNextArg(arg) && i+1 < len(rawArgs) {
			i++
			args = append(args, rawArgs[i])
		}
	}
	return append(args, extra...)
}

func stripChildRuntimeFlag(arg string) (string, bool) {
	switch arg {
	case "--wingui", "--version":
		return "", false
	case "-V":
		return "", false
	}
	if strings.HasPrefix(arg, "--") || !strings.HasPrefix(arg, "-") || arg == "-" {
		return arg, true
	}
	if strings.HasPrefix(arg, "-dynamicproxy://") || strings.HasPrefix(arg, "-ltcp://") || strings.HasPrefix(arg, "-rtcp://") {
		return arg, true
	}

	flagStr := arg[1:]
	var b strings.Builder
	for i := 0; i < len(flagStr); i++ {
		ch := flagStr[i]
		if ch == 'V' {
			continue
		}
		b.WriteByte(ch)
		if shortOptionRequiresArg(ch) {
			if i+1 < len(flagStr) {
				b.WriteString(flagStr[i+1:])
			}
			break
		}
	}
	if b.Len() == 0 {
		return "", false
	}
	return "-" + b.String(), true
}

func optionConsumesNextArg(arg string) bool {
	switch arg {
	case "--socks", "--socks-user", "--socks-pass",
		"--password", "--password-env", "--password-file",
		"--secondhost", "--secondhostkey", "--secondhostpass",
		"--keys", "--passwords", "--gui-internal-list",
		"--rsync-upload", "--rsync-download", "--scp-upload", "--scp-download",
		"--reconnect-delay":
		return true
	}
	if strings.HasPrefix(arg, "--") || !strings.HasPrefix(arg, "-") || arg == "-" {
		return false
	}
	if strings.HasPrefix(arg, "-dynamicproxy://") || strings.HasPrefix(arg, "-ltcp://") || strings.HasPrefix(arg, "-rtcp://") {
		return false
	}
	flagStr := arg[1:]
	for i := 0; i < len(flagStr); i++ {
		ch := flagStr[i]
		if shortOptionRequiresArg(ch) {
			return i+1 == len(flagStr)
		}
	}
	return false
}

func shortOptionRequiresArg(ch byte) bool {
	return strings.ContainsRune("bcDEeFiJLlmopRW", rune(ch))
}

func buildTransferArgs(protocol string, upload bool, directory bool, sources []string, target string) (string, string, error) {
	if len(sources) == 0 {
		return "", "", fmt.Errorf("no selected sources")
	}
	if target == "" {
		return "", "", fmt.Errorf("empty transfer target")
	}

	var flag string
	parts := make([]string, 0, len(sources)+3)
	switch protocol {
	case "scp":
		if upload {
			flag = "--scp-upload"
		} else {
			flag = "--scp-download"
		}
		if directory {
			parts = append(parts, "-r")
		}
	case "rsync":
		if upload {
			flag = "--rsync-upload"
		} else {
			flag = "--rsync-download"
		}
		parts = append(parts, "-avh")
	default:
		return "", "", fmt.Errorf("unsupported transfer protocol: %s", protocol)
	}

	// The GUI passes full local paths or rooted remote paths here, so names like
	// "-foo" arrive as "C:\\dir\\-foo" or "/dir/-foo" and do not need "--".
	for _, source := range sources {
		parts = append(parts, shellQuote(source))
	}
	parts = append(parts, shellQuote(target))
	return flag, strings.Join(parts, " "), nil
}

func normalizeLocalTransferPath(path string) string {
	if len(path) >= 2 && path[1] == ':' && isASCIILetter(path[0]) {
		if len(path) == 2 {
			return path + `\`
		}
		if path[2] != '\\' && path[2] != '/' {
			return path[:2] + `\` + path[2:]
		}
	}
	return path
}

func isASCIILetter(ch byte) bool {
	return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
}

func formatChildCommand(executable string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, filepath.Base(executable))
	for _, arg := range redactDisplayArgs(args) {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " ")
}

func redactDisplayArgs(args []string) []string {
	sensitive := map[string]bool{
		"--password":       true,
		"--passwords":      true,
		"--socks-pass":     true,
		"--secondhost":     true,
		"--secondhostpass": true,
	}
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if sensitive[arg] {
			out = append(out, arg)
			if i+1 < len(args) {
				out = append(out, "******")
				i++
			}
			continue
		}
		redacted := false
		for prefix := range sensitive {
			if strings.HasPrefix(arg, prefix+"=") {
				out = append(out, prefix+"=******")
				redacted = true
				break
			}
		}
		if !redacted {
			out = append(out, redactInlinePassword(arg))
		}
	}
	return out
}

func redactInlinePassword(arg string) string {
	at := strings.LastIndex(arg, "@")
	if at <= 0 {
		return arg
	}
	userInfo := arg[:at]
	colon := strings.Index(userInfo, ":")
	if colon < 0 || strings.ContainsAny(userInfo, `/\`) {
		return arg
	}
	return userInfo[:colon+1] + "******" + arg[at:]
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func displayName(name string, isDir bool) string {
	if isDir {
		return name + "/"
	}
	return name
}

func formatEntryDisplay(name string, isDir bool, size int64, mtime int64) string {
	kind := formatSize(size)
	if isDir {
		kind = "<DIR>"
	}
	when := ""
	if mtime > 0 {
		when = time.Unix(mtime, 0).Format("2006-01-02 15:04")
	}
	return fmt.Sprintf("%-42s %10s  %s", displayName(name, isDir), kind, when)
}

func formatSize(size int64) string {
	if size < 0 {
		size = 0
	}
	const unit = int64(1024)
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	value := float64(size)
	for _, suffix := range []string{"KB", "MB", "GB", "TB"} {
		value /= float64(unit)
		if value < float64(unit) {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1f PB", value/float64(unit))
}
