package transfer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/flyssh/flyssh/pkg/auth"
	"github.com/flyssh/flyssh/pkg/cli"
)

const (
	InternalRsyncTransportFlag = "--internal-rsync-transport"
	InternalRsyncOptionsEnv    = "FLYSSH_INTERNAL_RSYNC_OPTIONS_B64"
	rsyncPlaceholderHost       = "flyssh"
)

var lookPath = exec.LookPath
var executablePath = os.Executable
var startPromptBroker = auth.StartPromptBroker
var rsyncPathExists = func(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
var runRsyncListOnly = func(rsyncBin, path string) error {
	cmd := exec.Command(rsyncBin, "--list-only", path)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

type rsyncLocalPathStyle int
type rsyncLocalPathMode int

const (
	rsyncPathStyleCygdrive rsyncLocalPathStyle = iota + 1
	rsyncPathStyleMsys
)

const (
	rsyncLocalPathDefault rsyncLocalPathMode = iota
	rsyncLocalPathCygdrive
	rsyncLocalPathMsys
	rsyncLocalPathNative
)

var rsyncLocalPathStyleCache sync.Map

func RunLocalRsync(opts *cli.Options, spec *Spec) (int, error) {
	rsyncBin, err := resolveRsyncBinary()
	if err != nil {
		return 1, err
	}

	executable, err := executablePath()
	if err != nil {
		return 1, fmt.Errorf("resolve current executable: %w", err)
	}
	payload, err := EncodeInternalRsyncOptions(opts)
	if err != nil {
		return 1, err
	}
	var cleanupBroker func()
	brokerEnv, cleanupBroker, err := startPromptBroker()
	if err == nil {
		defer cleanupBroker()
	} else {
		brokerEnv = nil
		cleanupBroker = nil
		if opts.Verbose {
			fmt.Fprintf(os.Stderr, "flyssh: prompt broker unavailable, falling back to direct tty prompts: %v\n", err)
		}
	}

	args := buildRsyncCommandArgs(spec, executable, rsyncBin)
	code, err, stderrText := runLocalRsyncCommand(opts, rsyncBin, args, payload, brokerEnv)
	if err == nil {
		return code, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
		if shouldRetryRsyncWithAlternateWindowsPaths(spec, code, stderrText, runtime.GOOS) {
			for _, mode := range retryRsyncLocalPathModes() {
				retryArgs := buildRsyncCommandArgsWithLocalPathMode(spec, executable, rsyncBin, mode)
				if sameStringSlice(args, retryArgs) {
					continue
				}
				fmt.Fprintf(os.Stderr, "flyssh: rsync path style failed; retrying with %s Windows local paths\n", mode)
				code, err, stderrText = runLocalRsyncCommand(opts, rsyncBin, retryArgs, payload, brokerEnv)
				if err == nil {
					return code, nil
				}
				if retryExitErr, ok := err.(*exec.ExitError); ok {
					code = retryExitErr.ExitCode()
					if shouldRetryRsyncWithAlternateWindowsPaths(spec, code, stderrText, runtime.GOOS) {
						continue
					}
					return code, nil
				}
				return 1, fmt.Errorf("run local rsync retry: %w", err)
			}
		}
		return code, nil
	}
	return 1, fmt.Errorf("run local rsync: %w", err)
}

func runLocalRsyncCommand(opts *cli.Options, rsyncBin string, args []string, payload string, brokerEnv []string) (int, error, string) {
	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "flyssh: local rsync command: %s\n", formatRsyncCommand(rsyncBin, args))
	}
	var stderrBuf bytes.Buffer
	cmd := exec.Command(rsyncBin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)
	cmd.Env = append(os.Environ(), InternalRsyncOptionsEnv+"="+payload)
	cmd.Env = append(cmd.Env, brokerEnv...)

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), err, stderrBuf.String()
		}
		return 1, err, stderrBuf.String()
	}
	return 0, nil, stderrBuf.String()
}

func EncodeInternalRsyncOptions(opts *cli.Options) (string, error) {
	clone := cloneOptions(opts)
	clone.Command = ""
	clone.NoCommand = false
	clone.ShowVersion = false
	clone.Verbose = false
	clone.Wingui = false
	clone.GuiInternalHome = false
	clone.GuiInternalList = ""
	clone.RsyncUpload = ""
	clone.RsyncDownload = ""
	clone.ScpUpload = ""
	clone.ScpDownload = ""

	data, err := json.Marshal(clone)
	if err != nil {
		return "", fmt.Errorf("encode rsync transport options: %w", err)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func DecodeInternalRsyncOptions(payload string) (*cli.Options, error) {
	if payload == "" {
		return nil, fmt.Errorf("missing %s", InternalRsyncOptionsEnv)
	}
	data, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("decode rsync transport options: %w", err)
	}
	var opts cli.Options
	if err := json.Unmarshal(data, &opts); err != nil {
		return nil, fmt.Errorf("decode rsync transport options: %w", err)
	}
	return &opts, nil
}

func buildRsyncCommandArgs(spec *Spec, executable, rsyncBin string) []string {
	return buildRsyncCommandArgsWithLocalPathMode(spec, executable, rsyncBin, rsyncLocalPathDefault)
}

func buildRsyncCommandArgsWithLocalPathMode(spec *Spec, executable, rsyncBin string, mode rsyncLocalPathMode) []string {
	args := []string{"-e", buildRsyncTransportCommand(executable)}
	args = append(args, spec.Flags...)

	switch spec.Direction {
	case DirectionUpload:
		for _, src := range spec.Sources {
			args = append(args, rsyncSafeLocalPathWithMode(src, rsyncBin, mode))
		}
		args = append(args, buildInternalRemoteOperand(spec.Target))
	case DirectionDownload:
		for _, source := range spec.Sources {
			args = append(args, buildInternalRemoteOperand(source))
		}
		args = append(args, rsyncSafeLocalPathWithMode(spec.Target, rsyncBin, mode))
	}
	return args
}

func formatRsyncCommand(rsyncBin string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, shellEscape(rsyncBin))
	for _, arg := range args {
		parts = append(parts, shellEscape(arg))
	}
	return strings.Join(parts, " ")
}

func buildRsyncTransportCommand(executable string) string {
	return shellEscape(executable) + " " + shellEscape(InternalRsyncTransportFlag)
}

func buildInternalRemoteOperand(path string) string {
	return rsyncPlaceholderHost + ":" + path
}

func rsyncSafeLocalPath(p, rsyncBin string) string {
	return rsyncSafeLocalPathWithMode(p, rsyncBin, rsyncLocalPathDefault)
}

func rsyncSafeLocalPathWithMode(p, rsyncBin string, mode rsyncLocalPathMode) string {
	return rsyncSafeLocalPathForOSWithMode(p, rsyncBin, runtime.GOOS, mode)
}

func rsyncSafeLocalPathForOS(p, rsyncBin, goos string) string {
	return rsyncSafeLocalPathForOSWithMode(p, rsyncBin, goos, rsyncLocalPathDefault)
}

func rsyncSafeLocalPathForOSWithMode(p, rsyncBin, goos string, mode rsyncLocalPathMode) string {
	if goos != "windows" || !isWindowsDrivePath(p) {
		return p
	}
	switch mode {
	case rsyncLocalPathCygdrive:
		return convertWindowsDrivePath(p, rsyncPathStyleCygdrive)
	case rsyncLocalPathMsys:
		return convertWindowsDrivePath(p, rsyncPathStyleMsys)
	case rsyncLocalPathNative:
		return p
	}
	if style, ok := probeRsyncLocalPathStyle(rsyncBin, p); ok {
		return convertWindowsDrivePath(p, style)
	}
	if rsyncUsesCygdrive(rsyncBin) {
		return convertWindowsDrivePath(p, rsyncPathStyleCygdrive)
	}
	return convertWindowsDrivePath(p, rsyncPathStyleMsys)
}

func retryRsyncLocalPathModes() []rsyncLocalPathMode {
	return []rsyncLocalPathMode{rsyncLocalPathCygdrive, rsyncLocalPathMsys, rsyncLocalPathNative}
}

func (mode rsyncLocalPathMode) String() string {
	switch mode {
	case rsyncLocalPathCygdrive:
		return "/cygdrive"
	case rsyncLocalPathMsys:
		return "/drive"
	case rsyncLocalPathNative:
		return "native"
	default:
		return "default"
	}
}

func shouldRetryRsyncWithAlternateWindowsPaths(spec *Spec, exitCode int, stderrText, goos string) bool {
	if goos != "windows" || exitCode != 23 || !hasWindowsLocalRsyncOperand(spec) {
		return false
	}
	return strings.Contains(stderrText, "change_dir ") &&
		(strings.Contains(stderrText, `"/cygdrive/`) || containsQuotedMsysDrivePath(stderrText))
}

func hasWindowsLocalRsyncOperand(spec *Spec) bool {
	switch spec.Direction {
	case DirectionUpload:
		for _, src := range spec.Sources {
			if isWindowsDrivePath(src) {
				return true
			}
		}
	case DirectionDownload:
		return isWindowsDrivePath(spec.Target)
	}
	return false
}

func containsQuotedMsysDrivePath(s string) bool {
	for drive := byte('a'); drive <= 'z'; drive++ {
		if strings.Contains(s, `"/`+string(drive)+`/`) {
			return true
		}
	}
	return false
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func convertWindowsDrivePath(p string, style rsyncLocalPathStyle) string {
	drive := strings.ToLower(p[:1])
	rest := strings.ReplaceAll(p[2:], "\\", "/")
	rest = strings.TrimLeft(rest, "/")
	if style == rsyncPathStyleCygdrive {
		if rest == "" {
			return "/cygdrive/" + drive + "/"
		}
		return "/cygdrive/" + drive + "/" + rest
	}
	if rest == "" {
		return "/" + drive + "/"
	}
	return "/" + drive + "/" + rest
}

func probeRsyncLocalPathStyle(rsyncBin, nativePath string) (rsyncLocalPathStyle, bool) {
	if cached, ok := rsyncLocalPathStyleCache.Load(rsyncBin); ok {
		return cached.(rsyncLocalPathStyle), true
	}
	if !rsyncPathExists(nativePath) {
		return 0, false
	}
	for _, style := range []rsyncLocalPathStyle{rsyncPathStyleCygdrive, rsyncPathStyleMsys} {
		if runRsyncListOnly(rsyncBin, convertWindowsDrivePath(nativePath, style)) == nil {
			rsyncLocalPathStyleCache.Store(rsyncBin, style)
			return style, true
		}
	}
	return 0, false
}

func isWindowsDrivePath(p string) bool {
	return len(p) >= 2 && p[1] == ':' &&
		((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z'))
}

func rsyncUsesCygdrive(rsyncBin string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(rsyncBin, "\\", "/"))
	switch {
	case strings.Contains(normalized, "cygwin"):
		return true
	case strings.Contains(normalized, "cwrsync"):
		return true
	case strings.Contains(normalized, "/icw/"):
		return true
	case strings.Contains(normalized, "msys"):
		return false
	case strings.Contains(normalized, "mingw"):
		return false
	}
	dir := filepath.Dir(rsyncBin)
	if _, err := os.Stat(filepath.Join(dir, "cygwin1.dll")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "msys-2.0.dll")); err == nil {
		return false
	}
	return true
}

func cloneOptions(opts *cli.Options) *cli.Options {
	clone := *opts
	if opts.IdentityFiles != nil {
		clone.IdentityFiles = append([]string(nil), opts.IdentityFiles...)
	}
	if opts.LocalForwards != nil {
		clone.LocalForwards = append([]string(nil), opts.LocalForwards...)
	}
	if opts.RemoteForwards != nil {
		clone.RemoteForwards = append([]string(nil), opts.RemoteForwards...)
	}
	if opts.DynamicForwards != nil {
		clone.DynamicForwards = append([]string(nil), opts.DynamicForwards...)
	}
	if opts.SendEnv != nil {
		clone.SendEnv = append([]string(nil), opts.SendEnv...)
	}
	if opts.ExtraHosts != nil {
		clone.ExtraHosts = append([]string(nil), opts.ExtraHosts...)
	}
	if opts.SSHOptions != nil {
		clone.SSHOptions = make(map[string]string, len(opts.SSHOptions))
		for k, v := range opts.SSHOptions {
			clone.SSHOptions[k] = v
		}
	}
	return &clone
}

func BuildRemoteRsyncCommand(args []string) string {
	escaped := make([]string, 0, len(args))
	for _, arg := range args {
		escaped = append(escaped, shellEscape(arg))
	}
	return strings.Join(escaped, " ")
}
