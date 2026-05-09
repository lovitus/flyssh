package wingui

import (
	"fmt"
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
		parts = append(parts, "-a")
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
