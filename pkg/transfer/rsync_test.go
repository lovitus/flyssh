package transfer

import (
	"fmt"
	"io"
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

	got := buildRsyncCommandArgs(spec, "/tmp/flyssh", "/usr/bin/rsync")
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

	got := buildRsyncCommandArgs(spec, "/tmp/flyssh", "/usr/bin/rsync")
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

func TestFormatRsyncCommandQuotesArgs(t *testing.T) {
	got := formatRsyncCommand(`C:\Program Files\cwRsync\bin\rsync.exe`, []string{
		"-e",
		`'C:\Program Files\flyssh\flyssh.exe' '--internal-rsync-transport'`,
		"-avh",
		"flyssh:/remote/a dir",
		`/cygdrive/c/Users/leaf/Downloads`,
	})
	for _, want := range []string{
		`'C:\Program Files\cwRsync\bin\rsync.exe'`,
		`'-e'`,
		`'flyssh:/remote/a dir'`,
		`'/cygdrive/c/Users/leaf/Downloads'`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatted command %q missing %q", got, want)
		}
	}
}

func TestRsyncSafeLocalPathForWindowsCygwinRsync(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		rsyncBin string
		want     string
	}{
		{
			name:     "cygwin",
			path:     `E:\aria2-down`,
			rsyncBin: `C:\cygwin64\bin\rsync.exe`,
			want:     `/cygdrive/e/aria2-down`,
		},
		{
			name:     "cwrsync",
			path:     `E:\aria2-down`,
			rsyncBin: `C:\Program Files\cwRsync\bin\rsync.exe`,
			want:     `/cygdrive/e/aria2-down`,
		},
		{
			name:     "root",
			path:     `E:\`,
			rsyncBin: `C:\cygwin64\bin\rsync.exe`,
			want:     `/cygdrive/e/`,
		},
		{
			name:     "forward slashes",
			path:     `E:/aria2-down`,
			rsyncBin: `C:\cygwin64\bin\rsync.exe`,
			want:     `/cygdrive/e/aria2-down`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rsyncSafeLocalPathForOS(tt.path, tt.rsyncBin, "windows")
			if got != tt.want {
				t.Fatalf("unexpected path: got %q want %q", got, tt.want)
			}
		})
	}
}

func TestRsyncSafeLocalPathForWindowsMsysRsync(t *testing.T) {
	got := rsyncSafeLocalPathForOS(`E:\aria2-down`, `C:\msys64\usr\bin\rsync.exe`, "windows")
	if got != "/e/aria2-down" {
		t.Fatalf("unexpected path: got %q", got)
	}
}

func TestRsyncSafeLocalPathRetryModes(t *testing.T) {
	got := rsyncSafeLocalPathForOSWithMode(`E:\aria2-down\a b.txt`, `C:\cygwin64\bin\rsync.exe`, "windows", rsyncLocalPathMsys)
	if got != `/e/aria2-down/a b.txt` {
		t.Fatalf("unexpected msys path: got %q", got)
	}
	got = rsyncSafeLocalPathForOSWithMode(`E:\aria2-down\a b.txt`, `C:\cygwin64\bin\rsync.exe`, "windows", rsyncLocalPathCygdrive)
	if got != `/cygdrive/e/aria2-down/a b.txt` {
		t.Fatalf("unexpected cygdrive path: got %q", got)
	}
}

func TestBuildRsyncUploadArgsRelativeToCommonDir(t *testing.T) {
	spec := &Spec{
		Mode:      ModeRsync,
		Direction: DirectionUpload,
		Flags:     []string{"-avh"},
		Sources: []string{
			`D:\Deploy_部署\BPM v1.1\bpm-model.jar`,
			`D:\Deploy_部署\BPM v1.1\bpm-runtime.jar`,
		},
		Target: "/tmp/llf",
	}

	args, workDir, ok := buildRsyncUploadArgsRelativeToCommonDir(spec, `C:\flyssh\flyssh.exe`)
	if !ok {
		t.Fatal("expected relative retry args")
	}
	if workDir != `D:\Deploy_部署\BPM v1.1` {
		t.Fatalf("unexpected work dir: %q", workDir)
	}
	want := []string{
		"-e", `'C:\flyssh\flyssh.exe' '--internal-rsync-transport'`,
		"-avh",
		"./bpm-model.jar",
		"./bpm-runtime.jar",
		"flyssh:/tmp/llf",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("unexpected relative args:\n got: %#v\nwant: %#v", args, want)
	}
}

func TestBuildRsyncUploadArgsRelativeToCommonDirRejectsMixedParents(t *testing.T) {
	spec := &Spec{
		Mode:      ModeRsync,
		Direction: DirectionUpload,
		Flags:     []string{"-avh"},
		Sources: []string{
			`D:\Deploy_部署\a.jar`,
			`E:\Deploy_部署\b.jar`,
		},
		Target: "/tmp/llf",
	}
	if _, _, ok := buildRsyncUploadArgsRelativeToCommonDir(spec, `C:\flyssh\flyssh.exe`); ok {
		t.Fatal("mixed Windows source parents should not use relative retry")
	}
}

func TestBuildRsyncFilesFromArgs(t *testing.T) {
	spec := &Spec{
		Mode:      ModeRsync,
		Direction: DirectionUpload,
		Flags:     []string{"-a", "-v", "-h"},
		Sources:   []string{`D:\Deploy_部署\BPM v1.1\bpm-model.jar`},
		Target:    "/tmp/llf",
	}
	got := buildRsyncFilesFromArgs(spec, `C:\flyssh\flyssh.exe`)
	want := []string{
		"-e", `'C:\flyssh\flyssh.exe' '--internal-rsync-transport'`,
		"-a", "-v", "-h", "-r",
		"--from0", "--files-from=-", ".",
		"flyssh:/tmp/llf",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected files-from args:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestEnsureRecursiveFlag(t *testing.T) {
	tests := []struct {
		name  string
		flags []string
		want  []string
	}{
		{name: "archive adds recursive", flags: []string{"-a", "-v"}, want: []string{"-a", "-v", "-r"}},
		{name: "archive long adds recursive", flags: []string{"--archive"}, want: []string{"--archive", "-r"}},
		{name: "existing recursive", flags: []string{"-a", "-r"}, want: []string{"-a", "-r"}},
		{name: "existing recursive long", flags: []string{"--archive", "--recursive"}, want: []string{"--archive", "--recursive"}},
		{name: "no recursive wins", flags: []string{"-a", "--no-recursive"}, want: []string{"-a", "--no-recursive"}},
		{name: "no archive", flags: []string{"-v", "-h"}, want: []string{"-v", "-h"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ensureRecursiveFlag(tt.flags)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("unexpected flags: got %#v want %#v", got, tt.want)
			}
		})
	}
}

func TestHasDeleteFlag(t *testing.T) {
	for _, flag := range []string{"--delete", "--delete-before", "--delete-during", "--delete-delay", "--delete-after", "--delete-excluded", "--del"} {
		t.Run(flag, func(t *testing.T) {
			if !hasDeleteFlag([]string{"-a", flag}) {
				t.Fatalf("expected %s to be treated as delete flag", flag)
			}
		})
	}
	if hasDeleteFlag([]string{"-a", "--max-delete", "10"}) {
		t.Fatal("--max-delete alone should not trigger grouped retry delete guard")
	}
	if hasDeleteFlag([]string{"-a", "--force"}) {
		t.Fatal("--force without a delete flag should not trigger grouped retry delete guard")
	}
}

func TestGroupSourcesByWindowsDir(t *testing.T) {
	groups, ok := groupSourcesByWindowsDir([]string{
		`D:\Deploy_部署\BPM v1.1\bpm-model.jar`,
		`D:\Deploy_部署\BPM v1.1\-foo.jar`,
		`E:\Other 路径\dir`,
		`D:\Deploy_部署\BPM v1.1\subdir\`,
	})
	if !ok {
		t.Fatal("expected Windows sources to group")
	}
	// Same normalized directory should reuse its first group, preserving source order
	// inside that group and preserving first-seen group ordering overall.
	want := []rsyncSourceGroup{
		{Dir: `D:\Deploy_部署\BPM v1.1`, Names: []string{"bpm-model.jar", "-foo.jar", "subdir"}},
		{Dir: `E:\Other 路径`, Names: []string{"dir"}},
	}
	if !reflect.DeepEqual(groups, want) {
		t.Fatalf("unexpected groups:\n got: %#v\nwant: %#v", groups, want)
	}

	if _, ok := groupSourcesByWindowsDir([]string{`D:\ok\a.jar`, `/tmp/b.jar`}); ok {
		t.Fatal("mixed Windows/POSIX sources should not group")
	}
}

func TestRsyncFilesFromGroupedRetrySkipsDeleteFlags(t *testing.T) {
	spec := &Spec{
		Mode:      ModeRsync,
		Direction: DirectionUpload,
		Flags:     []string{"-a", "--delete"},
		Sources: []string{
			`D:\Deploy_部署\a.jar`,
			`E:\Other\b.jar`,
		},
		Target: "/tmp/llf",
	}
	if _, ok := runRsyncFilesFromGroupedRetry(&cli.Options{}, spec, `C:\flyssh\flyssh.exe`, `C:\cygwin64\bin\rsync.exe`, "", nil); ok {
		t.Fatal("grouped files-from retry should be skipped for delete flags")
	}
}

func TestRsyncFilesFromInputUsesNULSeparatedNames(t *testing.T) {
	input := rsyncFilesFromInput(rsyncSourceGroup{
		Dir:   `D:\Deploy_部署\BPM v1.1`,
		Names: []string{"bpm model.jar", "-foo.jar", "目录"},
	})
	data, err := io.ReadAll(input)
	if err != nil {
		t.Fatalf("read files-from input: %v", err)
	}
	want := "bpm model.jar\x00-foo.jar\x00目录\x00"
	if string(data) != want {
		t.Fatalf("unexpected files-from input: got %q want %q", string(data), want)
	}
}

func TestShouldRetryRsyncWithAlternateWindowsPaths(t *testing.T) {
	spec := &Spec{
		Mode:      ModeRsync,
		Direction: DirectionUpload,
		Sources:   []string{`D:\Deploy_部署\BPM v1.1\bpm-model.jar`},
		Target:    "/tmp/llf",
	}
	stderrText := `rsync: [sender] change_dir "/cygdrive/c/Windows/System32/"/cygdrive/d/Deploy_部署/BPM v1.1" failed: No such file or directory (2)`

	if !shouldRetryRsyncWithAlternateWindowsPaths(spec, 23, stderrText, "windows") {
		t.Fatal("expected Windows rsync change_dir quote symptom to trigger native retry")
	}
	if shouldRetryRsyncWithAlternateWindowsPaths(spec, 23, stderrText, "linux") {
		t.Fatal("non-Windows should not retry")
	}
	if shouldRetryRsyncWithAlternateWindowsPaths(spec, 12, stderrText, "windows") {
		t.Fatal("unrelated exit code should not retry")
	}
	if shouldRetryRsyncWithAlternateWindowsPaths(&Spec{Mode: ModeRsync, Direction: DirectionUpload, Sources: []string{"./src"}, Target: "/tmp"}, 23, stderrText, "windows") {
		t.Fatal("non-Windows local operand should not retry")
	}
}

func TestRsyncSafeLocalPathProbesUnknownRsyncCygdriveStyle(t *testing.T) {
	resetRsyncLocalPathStyleCache()
	oldPathExists := rsyncPathExists
	oldRunRsyncListOnly := runRsyncListOnly
	defer func() {
		rsyncPathExists = oldPathExists
		runRsyncListOnly = oldRunRsyncListOnly
		resetRsyncLocalPathStyleCache()
	}()

	rsyncPathExists = func(path string) bool { return path == `E:\aria2-down` }
	runRsyncListOnly = func(_, path string) error {
		if path == "/cygdrive/e/aria2-down" {
			return nil
		}
		return fmt.Errorf("unsupported path style")
	}

	got := rsyncSafeLocalPathForOS(`E:\aria2-down`, `C:\tools\rsync.exe`, "windows")
	if got != "/cygdrive/e/aria2-down" {
		t.Fatalf("unexpected path: got %q", got)
	}
}

func TestRsyncSafeLocalPathProbesUnknownRsyncMsysStyle(t *testing.T) {
	resetRsyncLocalPathStyleCache()
	oldPathExists := rsyncPathExists
	oldRunRsyncListOnly := runRsyncListOnly
	defer func() {
		rsyncPathExists = oldPathExists
		runRsyncListOnly = oldRunRsyncListOnly
		resetRsyncLocalPathStyleCache()
	}()

	probed := make([]string, 0, 2)
	rsyncPathExists = func(path string) bool { return path == `E:\aria2-down` }
	runRsyncListOnly = func(_, path string) error {
		probed = append(probed, path)
		if path == "/e/aria2-down" {
			return nil
		}
		return fmt.Errorf("unsupported path style")
	}

	got := rsyncSafeLocalPathForOS(`E:\aria2-down`, `C:\tools\rsync.exe`, "windows")
	if got != "/e/aria2-down" {
		t.Fatalf("unexpected path: got %q", got)
	}
	wantProbed := []string{"/cygdrive/e/aria2-down", "/e/aria2-down"}
	if !reflect.DeepEqual(probed, wantProbed) {
		t.Fatalf("unexpected probe order: got %#v want %#v", probed, wantProbed)
	}
}

func TestRsyncSafeLocalPathFallsBackWhenProbePathMissing(t *testing.T) {
	resetRsyncLocalPathStyleCache()
	oldPathExists := rsyncPathExists
	oldRunRsyncListOnly := runRsyncListOnly
	defer func() {
		rsyncPathExists = oldPathExists
		runRsyncListOnly = oldRunRsyncListOnly
		resetRsyncLocalPathStyleCache()
	}()

	rsyncPathExists = func(string) bool { return false }
	runRsyncListOnly = func(_, path string) error {
		t.Fatalf("probe should not run for missing native path, got %q", path)
		return nil
	}

	got := rsyncSafeLocalPathForOS(`E:\new-target`, `C:\tools\rsync.exe`, "windows")
	if got != "/cygdrive/e/new-target" {
		t.Fatalf("unexpected fallback path: got %q", got)
	}
}

func TestRsyncSafeLocalPathLeavesNonWindowsDrivePathsUnchanged(t *testing.T) {
	tests := []struct {
		name string
		path string
		goos string
	}{
		{name: "non windows", path: `E:\aria2-down`, goos: "linux"},
		{name: "relative", path: `.\aria2-down`, goos: "windows"},
		{name: "posix", path: `/tmp/aria2-down`, goos: "windows"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rsyncSafeLocalPathForOS(tt.path, `C:\cygwin64\bin\rsync.exe`, tt.goos)
			if got != tt.path {
				t.Fatalf("unexpected path: got %q want %q", got, tt.path)
			}
		})
	}
}

func resetRsyncLocalPathStyleCache() {
	rsyncLocalPathStyleCache.Range(func(key, _ any) bool {
		rsyncLocalPathStyleCache.Delete(key)
		return true
	})
}

func TestEncodeInternalRsyncOptionsClearsTransferFields(t *testing.T) {
	opts := &cli.Options{
		Host:            "host",
		User:            "user",
		IdentityFiles:   []string{"id_rsa"},
		SSHOptions:      map[string]string{"StrictHostKeyChecking": "no"},
		RsyncUpload:     "-avz ./src /dst",
		Wingui:          true,
		GuiInternalHome: true,
		GuiInternalList: "/tmp",
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
	if decoded.Wingui || decoded.GuiInternalHome || decoded.GuiInternalList != "" {
		t.Fatalf("GUI fields were not cleared: %+v", decoded)
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
