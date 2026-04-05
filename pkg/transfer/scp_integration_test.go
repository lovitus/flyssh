package transfer

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/flyssh/flyssh/internal/testkit"
	"golang.org/x/crypto/ssh"
)

func TestSCPUploadFile(t *testing.T) {
	server := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTransferSSH(t, server.Addr, "u1", "p1")
	defer client.Close()

	var status bytes.Buffer
	prevWriter := scpStatusWriter
	prevIsTerminal := scpStatusWriterIsTerminal
	scpStatusWriter = &status
	scpStatusWriterIsTerminal = func(io.Writer) bool { return true }
	defer func() {
		scpStatusWriter = prevWriter
		scpStatusWriterIsTerminal = prevIsTerminal
	}()

	localDir := t.TempDir()
	remoteDir := t.TempDir()
	localFile := filepath.Join(localDir, "hello.txt")
	if err := os.WriteFile(localFile, []byte("hello upload"), 0o644); err != nil {
		t.Fatalf("write local file: %v", err)
	}
	target := filepath.Join(remoteDir, "uploaded.txt")

	spec := &Spec{
		Mode:      ModeSCP,
		Direction: DirectionUpload,
		Sources:   []string{localFile},
		Target:    target,
	}
	code, err := Run(client, spec)
	if err != nil || code != 0 {
		t.Fatalf("Run upload: code=%d err=%v", code, err)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read uploaded file: %v", err)
	}
	if string(data) != "hello upload" {
		t.Fatalf("unexpected uploaded contents: %q", data)
	}
	output := status.String()
	if !strings.Contains(output, "Transfer starting: 1 path(s) via scp upload") {
		t.Fatalf("missing start output: %q", output)
	}
	if !strings.Contains(output, strconv.Quote(localFile)+" (file 1, 12 B)") {
		t.Fatalf("missing file progress output: %q", output)
	}
	if !strings.Contains(output, "Transfer complete: 1 file(s), 12 B transferred via scp upload") {
		t.Fatalf("missing completion output: %q", output)
	}
}

func TestSCPDownloadFileToDirectory(t *testing.T) {
	server := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTransferSSH(t, server.Addr, "u1", "p1")
	defer client.Close()

	var status bytes.Buffer
	prevWriter := scpStatusWriter
	prevIsTerminal := scpStatusWriterIsTerminal
	scpStatusWriter = &status
	scpStatusWriterIsTerminal = func(io.Writer) bool { return true }
	defer func() {
		scpStatusWriter = prevWriter
		scpStatusWriterIsTerminal = prevIsTerminal
	}()

	remoteDir := t.TempDir()
	localDir := t.TempDir()
	remoteFile := filepath.Join(remoteDir, "download.txt")
	if err := os.WriteFile(remoteFile, []byte("hello download"), 0o644); err != nil {
		t.Fatalf("write remote file: %v", err)
	}

	spec := &Spec{
		Mode:      ModeSCP,
		Direction: DirectionDownload,
		Sources:   []string{remoteFile},
		Target:    localDir,
	}
	code, err := Run(client, spec)
	if err != nil || code != 0 {
		t.Fatalf("Run download: code=%d err=%v", code, err)
	}

	data, err := os.ReadFile(filepath.Join(localDir, filepath.Base(remoteFile)))
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(data) != "hello download" {
		t.Fatalf("unexpected downloaded contents: %q", data)
	}
	output := status.String()
	if !strings.Contains(output, "Transfer starting: 1 path(s) via scp download") {
		t.Fatalf("missing start output: %q", output)
	}
	if !strings.Contains(output, strconv.Quote(filepath.Join(localDir, filepath.Base(remoteFile)))+" (file 1, 14 B)") {
		t.Fatalf("missing file progress output: %q", output)
	}
	if !strings.Contains(output, "Transfer complete: 1 file(s), 14 B transferred via scp download") {
		t.Fatalf("missing completion output: %q", output)
	}
}

func TestSCPUploadQuietSuppressesStatusOutput(t *testing.T) {
	server := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTransferSSH(t, server.Addr, "u1", "p1")
	defer client.Close()

	var status bytes.Buffer
	prevWriter := scpStatusWriter
	prevIsTerminal := scpStatusWriterIsTerminal
	scpStatusWriter = &status
	scpStatusWriterIsTerminal = func(io.Writer) bool { return true }
	defer func() {
		scpStatusWriter = prevWriter
		scpStatusWriterIsTerminal = prevIsTerminal
	}()

	localDir := t.TempDir()
	remoteDir := t.TempDir()
	localFile := filepath.Join(localDir, "quiet.txt")
	if err := os.WriteFile(localFile, []byte("quiet"), 0o644); err != nil {
		t.Fatalf("write local file: %v", err)
	}
	target := filepath.Join(remoteDir, "uploaded.txt")

	spec := &Spec{
		Mode:      ModeSCP,
		Direction: DirectionUpload,
		Flags:     []string{"-q"},
		Sources:   []string{localFile},
		Target:    target,
	}
	code, err := Run(client, spec)
	if err != nil || code != 0 {
		t.Fatalf("Run upload: code=%d err=%v", code, err)
	}
	if got := status.String(); got != "" {
		t.Fatalf("quiet mode should suppress transfer status output, got: %q", got)
	}
}

func TestSCPUploadNonTerminalSuppressesStatusOutput(t *testing.T) {
	server := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTransferSSH(t, server.Addr, "u1", "p1")
	defer client.Close()

	var status bytes.Buffer
	prevWriter := scpStatusWriter
	prevIsTerminal := scpStatusWriterIsTerminal
	scpStatusWriter = &status
	scpStatusWriterIsTerminal = func(io.Writer) bool { return false }
	defer func() {
		scpStatusWriter = prevWriter
		scpStatusWriterIsTerminal = prevIsTerminal
	}()

	localDir := t.TempDir()
	remoteDir := t.TempDir()
	localFile := filepath.Join(localDir, "silent.txt")
	if err := os.WriteFile(localFile, []byte("silent"), 0o644); err != nil {
		t.Fatalf("write local file: %v", err)
	}
	target := filepath.Join(remoteDir, "uploaded.txt")

	spec := &Spec{
		Mode:      ModeSCP,
		Direction: DirectionUpload,
		Sources:   []string{localFile},
		Target:    target,
	}
	code, err := Run(client, spec)
	if err != nil || code != 0 {
		t.Fatalf("Run upload: code=%d err=%v", code, err)
	}
	if got := status.String(); got != "" {
		t.Fatalf("non-terminal status output should be suppressed, got: %q", got)
	}
}

func TestIsTransferSuccess(t *testing.T) {
	if !isTransferSuccess(0, nil) {
		t.Fatal("expected success for code=0 err=nil")
	}
	if isTransferSuccess(1, nil) {
		t.Fatal("non-zero exit code must not be treated as success")
	}
	if isTransferSuccess(0, errors.New("boom")) {
		t.Fatal("error must not be treated as success")
	}
}

func TestSanitizeTransferStatusPath(t *testing.T) {
	path := "line1\nline2\t\x1b[31mred"
	got := sanitizeTransferStatusPath(path)
	want := strconv.Quote(path)
	if got != want {
		t.Fatalf("sanitizeTransferStatusPath() = %q, want %q", got, want)
	}
}

func TestSCPUploadRecursive(t *testing.T) {
	server := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTransferSSH(t, server.Addr, "u1", "p1")
	defer client.Close()

	localRoot := filepath.Join(t.TempDir(), "srcdir")
	if err := os.MkdirAll(filepath.Join(localRoot, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir local root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(localRoot, "nested", "file.txt"), []byte("nested"), 0o644); err != nil {
		t.Fatalf("write nested file: %v", err)
	}
	remoteTarget := filepath.Join(t.TempDir(), "remote-dir")

	spec := &Spec{
		Mode:      ModeSCP,
		Direction: DirectionUpload,
		Flags:     []string{"-r"},
		Sources:   []string{localRoot},
		Target:    remoteTarget,
	}
	code, err := Run(client, spec)
	if err != nil || code != 0 {
		t.Fatalf("Run recursive upload: code=%d err=%v", code, err)
	}

	data, err := os.ReadFile(filepath.Join(remoteTarget, "nested", "file.txt"))
	if err != nil {
		t.Fatalf("read recursive upload result: %v", err)
	}
	if string(data) != "nested" {
		t.Fatalf("unexpected recursive upload contents: %q", data)
	}
}

func TestSCPUploadMultipleFilesToDirectory(t *testing.T) {
	server := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTransferSSH(t, server.Addr, "u1", "p1")
	defer client.Close()

	localDir := t.TempDir()
	first := filepath.Join(localDir, "first.txt")
	second := filepath.Join(localDir, "second.txt")
	if err := os.WriteFile(first, []byte("one"), 0o644); err != nil {
		t.Fatalf("write first file: %v", err)
	}
	if err := os.WriteFile(second, []byte("two"), 0o644); err != nil {
		t.Fatalf("write second file: %v", err)
	}

	remoteTarget := filepath.Join(t.TempDir(), "remote-target")
	if err := os.MkdirAll(remoteTarget, 0o755); err != nil {
		t.Fatalf("mkdir remote target: %v", err)
	}

	spec := &Spec{
		Mode:      ModeSCP,
		Direction: DirectionUpload,
		Sources:   []string{first, second},
		Target:    remoteTarget,
	}
	code, err := Run(client, spec)
	if err != nil || code != 0 {
		t.Fatalf("Run multi-source upload: code=%d err=%v", code, err)
	}

	for _, tc := range []struct {
		name string
		want string
	}{
		{name: "first.txt", want: "one"},
		{name: "second.txt", want: "two"},
	} {
		data, readErr := os.ReadFile(filepath.Join(remoteTarget, tc.name))
		if readErr != nil {
			t.Fatalf("read %s: %v", tc.name, readErr)
		}
		if string(data) != tc.want {
			t.Fatalf("unexpected contents for %s: %q", tc.name, data)
		}
	}
}

func TestSCPDownloadMultipleFilesToDirectory(t *testing.T) {
	server := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTransferSSH(t, server.Addr, "u1", "p1")
	defer client.Close()

	remoteDir := t.TempDir()
	first := filepath.Join(remoteDir, "first.txt")
	second := filepath.Join(remoteDir, "second.txt")
	if err := os.WriteFile(first, []byte("one"), 0o644); err != nil {
		t.Fatalf("write first remote file: %v", err)
	}
	if err := os.WriteFile(second, []byte("two"), 0o644); err != nil {
		t.Fatalf("write second remote file: %v", err)
	}

	localTarget := t.TempDir()
	spec := &Spec{
		Mode:      ModeSCP,
		Direction: DirectionDownload,
		Sources:   []string{first, second},
		Target:    localTarget,
	}
	code, err := Run(client, spec)
	if err != nil || code != 0 {
		t.Fatalf("Run multi-source download: code=%d err=%v", code, err)
	}

	for _, tc := range []struct {
		name string
		want string
	}{
		{name: "first.txt", want: "one"},
		{name: "second.txt", want: "two"},
	} {
		data, readErr := os.ReadFile(filepath.Join(localTarget, tc.name))
		if readErr != nil {
			t.Fatalf("read %s: %v", tc.name, readErr)
		}
		if string(data) != tc.want {
			t.Fatalf("unexpected contents for %s: %q", tc.name, data)
		}
	}
}

func TestSCPDownloadRejectsDirectoryWithoutRecursive(t *testing.T) {
	server := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTransferSSH(t, server.Addr, "u1", "p1")
	defer client.Close()

	remoteRoot := filepath.Join(t.TempDir(), "remote-dir")
	if err := os.MkdirAll(remoteRoot, 0o755); err != nil {
		t.Fatalf("mkdir remote dir: %v", err)
	}

	spec := &Spec{
		Mode:      ModeSCP,
		Direction: DirectionDownload,
		Sources:   []string{remoteRoot},
		Target:    filepath.Join(t.TempDir(), "local-copy"),
	}
	code, err := Run(client, spec)
	if err == nil || code == 0 {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "use -r") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSCPUploadPathWithSpacesAndLeadingDash(t *testing.T) {
	server := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTransferSSH(t, server.Addr, "u1", "p1")
	defer client.Close()

	localDir := t.TempDir()
	localFile := filepath.Join(localDir, "name with space.txt")
	if err := os.WriteFile(localFile, []byte("space"), 0o644); err != nil {
		t.Fatalf("write local file: %v", err)
	}
	remoteDir := t.TempDir()
	target := filepath.Join(remoteDir, "-leading name.txt")

	spec := &Spec{
		Mode:      ModeSCP,
		Direction: DirectionUpload,
		Sources:   []string{localFile},
		Target:    target,
	}
	code, err := Run(client, spec)
	if err != nil || code != 0 {
		t.Fatalf("Run upload with special path: code=%d err=%v", code, err)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target file: %v", err)
	}
	if string(data) != "space" {
		t.Fatalf("unexpected contents: %q", data)
	}
}

func TestSCPDownloadPathWithQuotesAndGlobCharacters(t *testing.T) {
	server := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTransferSSH(t, server.Addr, "u1", "p1")
	defer client.Close()

	remoteDir := t.TempDir()
	remoteFile := filepath.Join(remoteDir, "quote ' star * file?.txt")
	if err := os.WriteFile(remoteFile, []byte("quoted"), 0o644); err != nil {
		t.Fatalf("write remote file: %v", err)
	}

	localDir := t.TempDir()
	spec := &Spec{
		Mode:      ModeSCP,
		Direction: DirectionDownload,
		Sources:   []string{remoteFile},
		Target:    localDir,
	}
	code, err := Run(client, spec)
	if err != nil || code != 0 {
		t.Fatalf("Run quoted-path download: code=%d err=%v", code, err)
	}

	data, err := os.ReadFile(filepath.Join(localDir, filepath.Base(remoteFile)))
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(data) != "quoted" {
		t.Fatalf("unexpected contents: %q", data)
	}
}

func TestSCPDownloadRecursivePreserveMode(t *testing.T) {
	server := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTransferSSH(t, server.Addr, "u1", "p1")
	defer client.Close()

	remoteRoot := filepath.Join(t.TempDir(), "remote-tree")
	remoteNested := filepath.Join(remoteRoot, "nested")
	if err := os.MkdirAll(remoteNested, 0o755); err != nil {
		t.Fatalf("mkdir remote tree: %v", err)
	}
	remoteFile := filepath.Join(remoteNested, "file.txt")
	if err := os.WriteFile(remoteFile, []byte("nested"), 0o644); err != nil {
		t.Fatalf("write remote file: %v", err)
	}

	rootWhen := time.Unix(1700000000, 0)
	nestedWhen := time.Unix(1700000100, 0)
	fileWhen := time.Unix(1700000200, 0)
	if err := os.Chtimes(remoteRoot, rootWhen, rootWhen); err != nil {
		t.Fatalf("chtimes remote root: %v", err)
	}
	if err := os.Chtimes(remoteNested, nestedWhen, nestedWhen); err != nil {
		t.Fatalf("chtimes remote nested dir: %v", err)
	}
	if err := os.Chtimes(remoteFile, fileWhen, fileWhen); err != nil {
		t.Fatalf("chtimes remote file: %v", err)
	}

	localParent := t.TempDir()
	spec := &Spec{
		Mode:      ModeSCP,
		Direction: DirectionDownload,
		Flags:     []string{"-r", "-p"},
		Sources:   []string{remoteRoot},
		Target:    localParent,
	}
	code, err := Run(client, spec)
	if err != nil || code != 0 {
		t.Fatalf("Run recursive preserve download: code=%d err=%v", code, err)
	}

	localRoot := filepath.Join(localParent, filepath.Base(remoteRoot))
	for _, tc := range []struct {
		path string
		when time.Time
	}{
		{path: localRoot, when: rootWhen},
		{path: filepath.Join(localRoot, "nested"), when: nestedWhen},
		{path: filepath.Join(localRoot, "nested", "file.txt"), when: fileWhen},
	} {
		info, statErr := os.Stat(tc.path)
		if statErr != nil {
			t.Fatalf("stat %s: %v", tc.path, statErr)
		}
		if !info.ModTime().Equal(tc.when) {
			t.Fatalf("unexpected modtime for %s: got %v want %v", tc.path, info.ModTime(), tc.when)
		}
	}
}

func TestSCPPreserveMode(t *testing.T) {
	server := testkit.StartSSHServer(t, map[string]string{"u1": "p1"})
	client := dialTransferSSH(t, server.Addr, "u1", "p1")
	defer client.Close()

	localDir := t.TempDir()
	localFile := filepath.Join(localDir, "preserve.txt")
	when := time.Unix(1700000000, 0)
	if err := os.WriteFile(localFile, []byte("preserve"), 0o600); err != nil {
		t.Fatalf("write local file: %v", err)
	}
	if err := os.Chtimes(localFile, when, when); err != nil {
		t.Fatalf("chtimes local file: %v", err)
	}
	target := filepath.Join(t.TempDir(), "preserved.txt")

	spec := &Spec{
		Mode:      ModeSCP,
		Direction: DirectionUpload,
		Flags:     []string{"-p"},
		Sources:   []string{localFile},
		Target:    target,
	}
	code, err := Run(client, spec)
	if err != nil || code != 0 {
		t.Fatalf("Run preserve upload: code=%d err=%v", code, err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected mode: %v", info.Mode().Perm())
	}
	if !info.ModTime().Equal(when) {
		t.Fatalf("unexpected modtime: got %v want %v", info.ModTime(), when)
	}
}

func dialTransferSSH(t *testing.T, addr, user, pass string) *ssh.Client {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("ssh dial %s: %v", addr, err)
	}
	return client
}
