package wingui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/flyssh/flyssh/pkg/cli"
)

const promptNotice = "Running; answer prompts in terminal if shown"

type remoteEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"`
	Mode  string `json:"mode"`
	User  string `json:"user"`
	Group string `json:"group"`
}

type statFunc func(string) (os.FileInfo, error)

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

func connectionSummary(opts *cli.Options) string {
	if opts == nil {
		return ""
	}

	route := []string{formatConnectionEndpoint(opts.User, opts.Host, opts.Port > 0, opts.Port)}
	for _, rawHop := range opts.ExtraHosts {
		route = append(route, connectionEndpointFromRawHop(rawHop))
	}
	if len(opts.ExtraHosts) == 0 && opts.SecondHost != "" {
		route = append(route, formatConnectionEndpoint(opts.SecondHostUser, opts.SecondHostHostname, opts.SecondHostPort > 0, opts.SecondHostPort))
	}

	summary := strings.Join(route, " -> ")
	details := make([]string, 0, 2)
	if hops := len(route); hops > 1 {
		details = append(details, fmt.Sprintf("%d hops", hops))
	}
	if opts.SocksProxy != "" {
		details = append(details, "SOCKS "+opts.SocksProxy)
	}
	if len(details) > 0 {
		summary += " (" + strings.Join(details, ", ") + ")"
	}
	return summary
}

func connectionEndpointFromRawHop(rawHop string) string {
	hop, err := cli.ParseHopSpec(rawHop)
	if err != nil {
		return redactConnectionRawHop(rawHop)
	}
	return formatConnectionEndpoint(hop.User, hop.Host, rawHopHasExplicitPort(rawHop), hop.Port)
}

func formatConnectionEndpoint(user, host string, showPort bool, port int) string {
	endpoint := host
	if user != "" {
		endpoint = user + "@" + endpoint
	}
	if showPort && port > 0 {
		endpoint = fmt.Sprintf("%s:%d", endpoint, port)
	}
	return endpoint
}

func rawHopHasExplicitPort(rawHop string) bool {
	hostPart := rawHop
	if idx := strings.LastIndex(rawHop, "@"); idx >= 0 {
		hostPart = rawHop[idx+1:]
	}
	if strings.HasPrefix(hostPart, "[") {
		end := strings.LastIndex(hostPart, "]")
		return end >= 0 && strings.HasPrefix(hostPart[end+1:], ":")
	}
	return strings.Contains(hostPart, ":")
}

func redactConnectionRawHop(rawHop string) string {
	if idx := strings.LastIndex(rawHop, "@"); idx >= 0 {
		userPart := rawHop[:idx]
		hostPart := rawHop[idx+1:]
		if colon := strings.Index(userPart, ":"); colon >= 0 {
			userPart = userPart[:colon]
		}
		if userPart != "" {
			return userPart + "@" + hostPart
		}
		return hostPart
	}
	return rawHop
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

func buildRemoteDeleteCommand(targets []string) (string, error) {
	if len(targets) == 0 {
		return "", fmt.Errorf("no selected delete targets")
	}
	parts := []string{"sh", "-c", shellQuote(`while [ "$#" -gt 0 ]; do rm -rf -- "$1" || exit $?; shift; done`), "flyssh-rm"}
	for _, target := range targets {
		if target == "" {
			return "", fmt.Errorf("empty delete target")
		}
		parts = append(parts, shellQuote(target))
	}
	return strings.Join(parts, " "), nil
}

func buildRemoteRenameCommand(source, target string) (string, error) {
	if source == "" {
		return "", fmt.Errorf("empty rename source")
	}
	if strings.TrimSpace(target) == "" {
		return "", fmt.Errorf("empty rename target")
	}
	parts := []string{
		"sh",
		"-c",
		shellQuote(`mv -- "$1" "$2"`),
		"flyssh-mv",
		shellQuote(source),
		shellQuote(target),
	}
	return strings.Join(parts, " "), nil
}

func buildRemoteMkdirCommand(target string) (string, error) {
	if strings.TrimSpace(target) == "" {
		return "", fmt.Errorf("empty new folder target")
	}
	parts := []string{
		"sh",
		"-c",
		shellQuote(`mkdir -- "$1"`),
		"flyssh-mkdir",
		shellQuote(target),
	}
	return strings.Join(parts, " "), nil
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

func classifyDroppedPaths(paths []string) ([]string, bool, string, error) {
	return classifyDroppedPathsWithStat(paths, os.Stat)
}

func classifyDroppedPathsWithStat(paths []string, stat statFunc) ([]string, bool, string, error) {
	if len(paths) == 0 {
		return nil, false, "", fmt.Errorf("drop contains no files")
	}
	sources := make([]string, 0, len(paths))
	fileCount := 0
	dirCount := 0
	for _, path := range paths {
		source := normalizeLocalTransferPath(path)
		if source == "" {
			return nil, false, "", fmt.Errorf("drop contains an empty path")
		}
		info, err := stat(source)
		if err != nil {
			return nil, false, "", fmt.Errorf("cannot access dropped path %q: %w", source, err)
		}
		if info.IsDir() {
			dirCount++
		} else {
			fileCount++
		}
		sources = append(sources, source)
	}
	return sources, dirCount > 0, droppedPathsSummary(sources, fileCount, dirCount), nil
}

func droppedPathsSummary(sources []string, fileCount, dirCount int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d file(s), %d folder(s)", fileCount, dirCount)
	limit := len(sources)
	if limit > 5 {
		limit = 5
	}
	for i := 0; i < limit; i++ {
		b.WriteString("\r\n")
		b.WriteString(sources[i])
	}
	if more := len(sources) - limit; more > 0 {
		fmt.Fprintf(&b, "\r\n... and %d more", more)
	}
	return b.String()
}

func selectionSummary(paths []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d item(s)", len(paths))
	limit := len(paths)
	if limit > 5 {
		limit = 5
	}
	for i := 0; i < limit; i++ {
		b.WriteString("\r\n")
		b.WriteString(paths[i])
	}
	if more := len(paths) - limit; more > 0 {
		fmt.Fprintf(&b, "\r\n... and %d more", more)
	}
	return b.String()
}

func formatChildCommand(executable string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, quoteDisplayArg(filepath.Base(executable)))
	redacted := redactDisplayArgs(args)
	for i := 0; i < len(redacted); i++ {
		arg := redacted[i]
		parts = append(parts, quoteDisplayArg(arg))
		if isTransferFlag(arg) && i+1 < len(redacted) {
			i++
			parts = append(parts, formatTransferRawForDisplay(redacted[i]))
		}
	}
	return strings.Join(parts, " ")
}

func isTransferFlag(arg string) bool {
	switch arg {
	case "--scp-upload", "--scp-download", "--rsync-upload", "--rsync-download":
		return true
	default:
		return false
	}
}

func formatTransferRawForDisplay(raw string) string {
	words, err := splitDisplayShellWords(raw)
	if err != nil || len(words) == 0 {
		return quoteDisplayArg(raw)
	}
	parts := make([]string, 0, len(words))
	for _, word := range words {
		parts = append(parts, quoteDisplayArg(word))
	}
	return strings.Join(parts, " ")
}

func splitDisplayShellWords(raw string) ([]string, error) {
	var words []string
	var b strings.Builder
	inSingle := false
	inDouble := false
	escaped := false
	hadWord := false

	flush := func() {
		if hadWord {
			words = append(words, b.String())
			b.Reset()
			hadWord = false
		}
	}

	for _, r := range raw {
		switch {
		case escaped:
			b.WriteRune(r)
			hadWord = true
			escaped = false
		case r == '\\' && !inSingle:
			escaped = true
			hadWord = true
		case r == '\'' && !inDouble:
			inSingle = !inSingle
			hadWord = true
		case r == '"' && !inSingle:
			inDouble = !inDouble
			hadWord = true
		case (r == ' ' || r == '\t' || r == '\n' || r == '\r') && !inSingle && !inDouble:
			flush()
		default:
			b.WriteRune(r)
			hadWord = true
		}
	}
	if escaped {
		b.WriteRune('\\')
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("unterminated quote")
	}
	flush()
	return words, nil
}

func quoteDisplayArg(arg string) string {
	if arg == "" {
		return `""`
	}
	if !strings.ContainsAny(arg, " \t\r\n\"") {
		return arg
	}
	return `"` + strings.ReplaceAll(arg, `"`, `\"`) + `"`
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

func formatEntryDisplay(name string, isDir bool, size int64, mtime int64, mode, user, group string) string {
	kind := formatSize(size)
	if isDir {
		kind = "<DIR>"
	}
	when := "?"
	if mtime >= 0 {
		when = time.Unix(mtime, 0).Format("2006-01-02 15:04")
	}
	display := fmt.Sprintf("%-48s %12s %16s", displayName(name, isDir), kind, when)
	if meta := formatOwnerMode(mode, user, group); meta != "" {
		display += " " + meta
	}
	return display
}

func formatSize(size int64) string {
	if size < 0 {
		return "?"
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

func formatOwnerMode(mode, user, group string) string {
	mode = strings.TrimSpace(mode)
	user = strings.TrimSpace(user)
	group = strings.TrimSpace(group)
	owner := ""
	switch {
	case user != "" && group != "":
		owner = user + ":" + group
	case user != "":
		owner = user
	case group != "":
		owner = group
	}
	switch {
	case mode != "" && owner != "":
		return mode + " " + owner
	case mode != "":
		return mode
	default:
		return owner
	}
}
