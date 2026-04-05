package transfer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/flyssh/flyssh/pkg/cli"
)

func TestBuildRsyncCommandArgsUpload(t *testing.T) {
	spec := &Spec{
		Mode:      ModeRsync,
		Direction: DirectionUpload,
		Flags:     []string{"-avz", "--delete"},
		Sources:   []string{"./src", "./extra"},
		Target:    "/remote/dst",
	}

	got := buildRsyncCommandArgs(spec, "/tmp/flyssh")
	want := []string{
		"-e", "'/tmp/flyssh' '--internal-rsync-transport'",
		"-avz", "--delete",
		"./src", "./extra",
		"flyssh:/remote/dst",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected args:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestBuildRsyncCommandArgsDownload(t *testing.T) {
	spec := &Spec{
		Mode:      ModeRsync,
		Direction: DirectionDownload,
		Flags:     []string{"-avz"},
		Sources:   []string{"/remote/a", "/remote/b"},
		Target:    "./localdir",
	}

	got := buildRsyncCommandArgs(spec, "/tmp/flyssh")
	want := []string{
		"-e", "'/tmp/flyssh' '--internal-rsync-transport'",
		"-avz",
		"flyssh:/remote/a",
		"flyssh:/remote/b",
		"./localdir",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected args:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestEncodeInternalRsyncOptionsClearsTransferFields(t *testing.T) {
	opts := &cli.Options{
		Host:          "host",
		User:          "user",
		IdentityFiles: []string{"id_rsa"},
		SSHOptions:    map[string]string{"StrictHostKeyChecking": "no"},
		RsyncUpload:   "-avz ./src /dst",
	}

	payload, err := EncodeInternalRsyncOptions(opts)
	if err != nil {
		t.Fatalf("EncodeInternalRsyncOptions returned error: %v", err)
	}
	decoded, err := DecodeInternalRsyncOptions(payload)
	if err != nil {
		t.Fatalf("DecodeInternalRsyncOptions returned error: %v", err)
	}
	if decoded.RsyncUpload != "" || decoded.RsyncDownload != "" || decoded.ScpUpload != "" || decoded.ScpDownload != "" {
		t.Fatalf("transfer fields were not cleared: %+v", decoded)
	}
	if decoded.Host != "host" || decoded.User != "user" {
		t.Fatalf("connection fields lost during roundtrip: %+v", decoded)
	}
}

func TestRunLocalRsyncMissingBinary(t *testing.T) {
	oldLookPath := lookPath
	lookPath = func(string) (string, error) {
		return "", exec.ErrNotFound
	}
	defer func() { lookPath = oldLookPath }()

	code, err := RunLocalRsync(&cli.Options{Host: "host"}, &Spec{Mode: ModeRsync, Direction: DirectionUpload})
	if code == 0 || err == nil {
		t.Fatalf("expected missing binary error, got code=%d err=%v", code, err)
	}
	if !strings.Contains(err.Error(), "local rsync binary not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunLocalRsyncProvidesPromptBrokerEnv(t *testing.T) {
	tmpDir := t.TempDir()
	fakeRsync := filepath.Join(tmpDir, "rsync")
	envPath := filepath.Join(tmpDir, "env.txt")
	script := "#!/bin/sh\nprintf '%s\\n' \"$FLYSSH_PROMPT_BROKER_NETWORK\" > \"$CAPTURE_ENV\"\nprintf '%s\\n' \"$FLYSSH_PROMPT_BROKER_ADDR\" >> \"$CAPTURE_ENV\"\nprintf '%s\\n' \"$FLYSSH_PROMPT_BROKER_TOKEN\" >> \"$CAPTURE_ENV\"\nexit 0\n"
	if err := os.WriteFile(fakeRsync, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake rsync: %v", err)
	}

	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", tmpDir+string(os.PathListSeparator)+oldPath)
	t.Setenv("CAPTURE_ENV", envPath)

	oldLookPath := lookPath
	oldExecutablePath := executablePath
	lookPath = exec.LookPath
	executablePath = func() (string, error) { return "/tmp/flyssh-test", nil }
	defer func() {
		lookPath = oldLookPath
		executablePath = oldExecutablePath
	}()

	code, err := RunLocalRsync(
		&cli.Options{Host: "host", User: "user", Password: "secret"},
		&Spec{Mode: ModeRsync, Direction: DirectionUpload, Sources: []string{"./src"}, Target: "/dst"},
	)
	if err != nil || code != 0 {
		t.Fatalf("RunLocalRsync: code=%d err=%v", code, err)
	}

	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read captured env: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("unexpected captured env: %q", data)
	}
	if lines[0] == "" {
		t.Fatal("expected prompt broker network to be set")
	}
	if lines[1] == "" {
		t.Fatal("expected prompt broker address to be set")
	}
	if lines[2] == "" {
		t.Fatal("expected prompt broker token to be set")
	}
	if os.Getenv("FLYSSH_PROMPT_BROKER_NETWORK") != "" || os.Getenv("FLYSSH_PROMPT_BROKER_ADDR") != "" || os.Getenv("FLYSSH_PROMPT_BROKER_TOKEN") != "" {
		t.Fatal("broker env should only be set on the rsync child process")
	}
}

func TestRunLocalRsyncContinuesWhenPromptBrokerUnavailable(t *testing.T) {
	tmpDir := t.TempDir()
	fakeRsync := filepath.Join(tmpDir, "rsync")
	markerPath := filepath.Join(tmpDir, "ran.txt")
	script := "#!/bin/sh\nprintf ok > \"$RUN_MARKER\"\nexit 0\n"
	if err := os.WriteFile(fakeRsync, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake rsync: %v", err)
	}

	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", tmpDir+string(os.PathListSeparator)+oldPath)
	t.Setenv("RUN_MARKER", markerPath)

	oldLookPath := lookPath
	oldExecutablePath := executablePath
	oldStartPromptBroker := startPromptBroker
	startPromptBroker = func() ([]string, func(), error) {
		return nil, nil, fmt.Errorf("prompt broker unavailable")
	}
	lookPath = exec.LookPath
	executablePath = func() (string, error) { return "/tmp/flyssh-test", nil }
	defer func() {
		lookPath = oldLookPath
		executablePath = oldExecutablePath
		startPromptBroker = oldStartPromptBroker
	}()

	code, err := RunLocalRsync(
		&cli.Options{Host: "host", User: "user", Password: "secret"},
		&Spec{Mode: ModeRsync, Direction: DirectionUpload, Sources: []string{"./src"}, Target: "/dst"},
	)
	if err != nil || code != 0 {
		t.Fatalf("RunLocalRsync: code=%d err=%v", code, err)
	}

	data, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatalf("read run marker: %v", err)
	}
	if string(data) != "ok" {
		t.Fatalf("unexpected marker contents: %q", data)
	}
}

func TestSystemRsyncExecShape(t *testing.T) {
	if _, err := exec.LookPath("rsync"); err != nil {
		t.Skip("rsync not installed")
	}

	tmpDir := t.TempDir()
	capturePath := filepath.Join(tmpDir, "capture.sh")
	argsPath := filepath.Join(tmpDir, "args.txt")
	srcDir := filepath.Join(tmpDir, "src")
	if err := os.WriteFile(capturePath, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$TMP_CAPTURE\"\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("write capture script: %v", err)
	}
	if err := os.Mkdir(srcDir, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	cmd := exec.Command("rsync", "-av", "-e", capturePath, srcDir+"/", "dummyhost:/tmp/target")
	cmd.Env = append(os.Environ(), "TMP_CAPTURE="+argsPath)
	_ = cmd.Run()

	data, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 4 {
		t.Fatalf("unexpected captured argv: %q", data)
	}
	if lines[0] != "dummyhost" || lines[1] != "rsync" || lines[2] != "--server" {
		t.Fatalf("unexpected captured argv head: %#v", lines[:3])
	}
}
