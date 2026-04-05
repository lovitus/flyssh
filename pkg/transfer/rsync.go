package transfer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/flyssh/flyssh/pkg/cli"
)

const (
	InternalRsyncTransportFlag = "--internal-rsync-transport"
	InternalRsyncOptionsEnv    = "FLYSSH_INTERNAL_RSYNC_OPTIONS_B64"
	rsyncPlaceholderHost       = "flyssh"
)

var lookPath = exec.LookPath

func RunLocalRsync(opts *cli.Options, spec *Spec) (int, error) {
	if _, err := lookPath("rsync"); err != nil {
		return 1, fmt.Errorf("local rsync binary not found in PATH")
	}

	executable, err := os.Executable()
	if err != nil {
		return 1, fmt.Errorf("resolve current executable: %w", err)
	}
	payload, err := EncodeInternalRsyncOptions(opts)
	if err != nil {
		return 1, err
	}

	cmd := exec.Command("rsync", buildRsyncCommandArgs(spec, executable)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), InternalRsyncOptionsEnv+"="+payload)

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 1, fmt.Errorf("run local rsync: %w", err)
	}
	return 0, nil
}

func EncodeInternalRsyncOptions(opts *cli.Options) (string, error) {
	clone := cloneOptions(opts)
	clone.Command = ""
	clone.NoCommand = false
	clone.ShowVersion = false
	clone.Verbose = false
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

func buildRsyncCommandArgs(spec *Spec, executable string) []string {
	args := []string{"-e", buildRsyncTransportCommand(executable)}
	args = append(args, spec.Flags...)

	switch spec.Direction {
	case DirectionUpload:
		args = append(args, spec.Sources...)
		args = append(args, buildInternalRemoteOperand(spec.Target))
	case DirectionDownload:
		for _, source := range spec.Sources {
			args = append(args, buildInternalRemoteOperand(source))
		}
		args = append(args, spec.Target)
	}
	return args
}

func buildRsyncTransportCommand(executable string) string {
	return shellEscape(executable) + " " + shellEscape(InternalRsyncTransportFlag)
}

func buildInternalRemoteOperand(path string) string {
	return rsyncPlaceholderHost + ":" + path
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
