package wingui

import (
	"fmt"
	"path/filepath"
	"strings"
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
	for _, arg := range rawArgs {
		if arg == "--wingui" || arg == "--version" || arg == "-V" {
			continue
		}
		args = append(args, arg)
	}
	return append(args, extra...)
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
