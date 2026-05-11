package wingui

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBuildChildArgsRemovesWinguiAndKeepsRawSecrets(t *testing.T) {
	raw := []string{"--socks", "127.0.0.1:1080", "user@host", "--password", "secret", "--wingui"}
	got := buildChildArgs(raw, "--gui-internal-home")
	want := []string{"--socks", "127.0.0.1:1080", "user@host", "--password", "secret", "--gui-internal-home"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected child args:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestBuildChildArgsStripsVersionFlags(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "--version long flag",
			in:   []string{"--version", "user@host", "--wingui"},
			want: []string{"user@host"},
		},
		{
			name: "-V standalone",
			in:   []string{"-V", "user@host", "--wingui"},
			want: []string{"user@host"},
		},
		{
			name: "no version flag unchanged",
			in:   []string{"-v", "user@host", "--wingui"},
			want: []string{"-v", "user@host"},
		},
		{
			name: "value containing V not corrupted",
			in:   []string{"-lVincent", "host", "--wingui"},
			want: []string{"-lVincent", "host"},
		},
		{
			name: "combined version flag stripped",
			in:   []string{"-vV", "user@host", "--wingui"},
			want: []string{"-v", "user@host"},
		},
		{
			name: "short option value preserved",
			in:   []string{"-o", "-V", "user@host", "--wingui"},
			want: []string{"-o", "-V", "user@host"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildChildArgs(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("unexpected child args:\n got: %#v\nwant: %#v", got, tt.want)
			}
		})
	}
}

func TestBuildChildArgsPreservesRuntimeFlagLookingValues(t *testing.T) {
	raw := []string{"--password", "--wingui", "--passwords", "-V", "user@host", "--wingui", "--version"}
	got := buildChildArgs(raw, "--gui-internal-home")
	want := []string{"--password", "--wingui", "--passwords", "-V", "user@host", "--gui-internal-home"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected child args:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestBuildTransferArgsScenarios(t *testing.T) {
	tests := []struct {
		name      string
		protocol  string
		upload    bool
		directory bool
		sources   []string
		target    string
		wantFlag  string
		wantRaw   string
	}{
		{
			name:     "scp local files upload",
			protocol: "scp", upload: true,
			sources: []string{`C:\work\a b.txt`, `C:\work\中文.txt`}, target: "/tmp/out",
			wantFlag: "--scp-upload",
			wantRaw:  `'C:\work\a b.txt' 'C:\work\中文.txt' '/tmp/out'`,
		},
		{
			name: "scp remote dir download", protocol: "scp", upload: false, directory: true,
			sources: []string{"/tmp/a'b"}, target: `C:\out dir`,
			wantFlag: "--scp-download",
			wantRaw:  `-r '/tmp/a'"'"'b' 'C:\out dir'`,
		},
		{
			name: "rsync upload adds archive", protocol: "rsync", upload: true,
			sources: []string{`C:\src`}, target: "/tmp/out",
			wantFlag: "--rsync-upload",
			wantRaw:  `-avh 'C:\src' '/tmp/out'`,
		},
		{
			name: "rsync download adds archive", protocol: "rsync", upload: false,
			sources: []string{"/tmp/src"}, target: `C:\out`,
			wantFlag: "--rsync-download",
			wantRaw:  `-avh '/tmp/src' 'C:\out'`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag, raw, err := buildTransferArgs(tt.protocol, tt.upload, tt.directory, tt.sources, tt.target)
			if err != nil {
				t.Fatalf("buildTransferArgs returned error: %v", err)
			}
			if flag != tt.wantFlag || raw != tt.wantRaw {
				t.Fatalf("unexpected transfer args: flag=%q raw=%q", flag, raw)
			}
		})
	}
}

func TestFormatChildCommandRedactsSecrets(t *testing.T) {
	got := formatChildCommand(`C:\Tools\flyssh.exe`, []string{
		"--password", "secret",
		"--passwords=p1,p2",
		"root:inline@10.0.0.1",
		"--scp-download", `-r '/tmp/src' 'C:\out dir'`,
	})
	for _, forbidden := range []string{"secret", "p1,p2", "inline"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("command preview leaked %q in %q", forbidden, got)
		}
	}
	for _, want := range []string{"flyssh.exe", "--password", "******", "root:******@10.0.0.1", "--scp-download"} {
		if !strings.Contains(got, want) {
			t.Fatalf("command preview %q missing %q", got, want)
		}
	}
	if strings.Contains(got, `'"'"'`) {
		t.Fatalf("command preview should not expose POSIX quote escapes: %q", got)
	}
	for _, want := range []string{"-r", "/tmp/src", `"C:\out dir"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("command preview %q missing readable transfer arg %q", got, want)
		}
	}
}

func TestFormatChildCommandUsesReadableTransferArgs(t *testing.T) {
	got := formatChildCommand(`C:\flyssh\flyssh.exe`, []string{
		"uhome:pass@120.76.205.81:41122",
		"--rsync-upload",
		`-avh 'D:\Apps_lee\AnyDesk - Copy.exe' 'D:\Apps_lee\AnyDesk - Copy.zip' '/home/uhome/.local/.pki'`,
	})
	for _, forbidden := range []string{`'"'"'`, `'-avh`, `'D:\Apps_lee`} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("command preview should be human-readable, got %q", got)
		}
	}
	for _, want := range []string{
		"uhome:******@120.76.205.81:41122",
		"--rsync-upload",
		"-avh",
		`"D:\Apps_lee\AnyDesk - Copy.exe"`,
		`"D:\Apps_lee\AnyDesk - Copy.zip"`,
		"/home/uhome/.local/.pki",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("command preview %q missing %q", got, want)
		}
	}
}

func TestNormalizeLocalTransferPathAvoidsDriveRelativePaths(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "drive only", in: `D:`, want: `D:\`},
		{name: "drive relative", in: `D:Apps_lee\AnyDesk.zip`, want: `D:\Apps_lee\AnyDesk.zip`},
		{name: "absolute backslash", in: `D:\Apps_lee\AnyDesk.zip`, want: `D:\Apps_lee\AnyDesk.zip`},
		{name: "absolute slash", in: `D:/Apps_lee/AnyDesk.zip`, want: `D:/Apps_lee/AnyDesk.zip`},
		{name: "relative", in: `Apps_lee\AnyDesk.zip`, want: `Apps_lee\AnyDesk.zip`},
		{name: "remote style unchanged", in: `/tmp/file`, want: `/tmp/file`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeLocalTransferPath(tt.in)
			if got != tt.want {
				t.Fatalf("unexpected path: got %q want %q", got, tt.want)
			}
		})
	}
}

func TestClassifyDroppedPathsRejectsEmpty(t *testing.T) {
	_, _, _, err := classifyDroppedPathsWithStat(nil, fakeDropStat(nil))
	if err == nil {
		t.Fatal("expected empty drop error")
	}
}

func TestClassifyDroppedPathsMixedFilesAndDirs(t *testing.T) {
	sources, hasDir, summary, err := classifyDroppedPathsWithStat(
		[]string{`C:\src\a.txt`, `C:\src\folder`},
		fakeDropStat(map[string]bool{
			`C:\src\a.txt`:  false,
			`C:\src\folder`: true,
		}),
	)
	if err != nil {
		t.Fatalf("classifyDroppedPaths returned error: %v", err)
	}
	if !hasDir {
		t.Fatal("expected hasDir")
	}
	wantSources := []string{`C:\src\a.txt`, `C:\src\folder`}
	if !reflect.DeepEqual(sources, wantSources) {
		t.Fatalf("unexpected sources: got %#v want %#v", sources, wantSources)
	}
	for _, want := range []string{"1 file(s)", "1 folder(s)", `C:\src\a.txt`, `C:\src\folder`} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary %q missing %q", summary, want)
		}
	}
}

func TestClassifyDroppedPathsNormalizesDriveRelativePath(t *testing.T) {
	sources, hasDir, _, err := classifyDroppedPathsWithStat(
		[]string{`D:drop\file.txt`},
		fakeDropStat(map[string]bool{`D:\drop\file.txt`: false}),
	)
	if err != nil {
		t.Fatalf("classifyDroppedPaths returned error: %v", err)
	}
	if hasDir {
		t.Fatal("expected file-only drop")
	}
	if got, want := sources[0], `D:\drop\file.txt`; got != want {
		t.Fatalf("unexpected normalized source: got %q want %q", got, want)
	}
}

func TestClassifyDroppedPathsRejectsAnyInvalidPath(t *testing.T) {
	sources, hasDir, summary, err := classifyDroppedPathsWithStat(
		[]string{`C:\src\ok.txt`, `C:\src\missing.txt`},
		fakeDropStat(map[string]bool{`C:\src\ok.txt`: false}),
	)
	if err == nil {
		t.Fatal("expected invalid path error")
	}
	if sources != nil || hasDir || summary != "" {
		t.Fatalf("expected all-or-nothing failure, got sources=%#v hasDir=%v summary=%q", sources, hasDir, summary)
	}
}

func TestDropUploadTransferArgs(t *testing.T) {
	sources, hasDir, _, err := classifyDroppedPathsWithStat(
		[]string{`C:\src\a.txt`, `C:\src\folder`},
		fakeDropStat(map[string]bool{
			`C:\src\a.txt`:  false,
			`C:\src\folder`: true,
		}),
	)
	if err != nil {
		t.Fatalf("classifyDroppedPaths returned error: %v", err)
	}
	scpFlag, scpRaw, err := buildTransferArgs("scp", true, hasDir, sources, "/remote")
	if err != nil {
		t.Fatalf("buildTransferArgs scp: %v", err)
	}
	if scpFlag != "--scp-upload" || !strings.Contains(scpRaw, "-r") {
		t.Fatalf("unexpected scp drop args: flag=%q raw=%q", scpFlag, scpRaw)
	}
	rsyncFlag, rsyncRaw, err := buildTransferArgs("rsync", true, hasDir, sources, "/remote")
	if err != nil {
		t.Fatalf("buildTransferArgs rsync: %v", err)
	}
	if rsyncFlag != "--rsync-upload" || !strings.Contains(rsyncRaw, "-avh") {
		t.Fatalf("unexpected rsync drop args: flag=%q raw=%q", rsyncFlag, rsyncRaw)
	}
}

func TestBuildRemoteDeleteCommand(t *testing.T) {
	got, err := buildRemoteDeleteCommand([]string{"/tmp/a b", "/tmp/quote'file", "/tmp/-dash"})
	if err != nil {
		t.Fatalf("buildRemoteDeleteCommand returned error: %v", err)
	}
	for _, want := range []string{
		"sh -c",
		`'while [ "$#" -gt 0 ]; do rm -rf -- "$1" || exit $?; shift; done'`,
		"flyssh-rm",
		"'/tmp/a b'",
		`'/tmp/quote'"'"'file'`,
		"'/tmp/-dash'",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("command %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "$@") {
		t.Fatalf("delete command should not contain $@ because CLI hop parsing treats @ specially: %q", got)
	}
}

func TestBuildRemoteRenameCommand(t *testing.T) {
	got, err := buildRemoteRenameCommand("/tmp/a b", "/tmp/quote'file")
	if err != nil {
		t.Fatalf("buildRemoteRenameCommand returned error: %v", err)
	}
	for _, want := range []string{
		"sh -c",
		`'mv -- "$1" "$2"'`,
		"flyssh-mv",
		"'/tmp/a b'",
		`'/tmp/quote'"'"'file'`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("command %q missing %q", got, want)
		}
	}
}

func TestSelectionSummaryLimitsPreview(t *testing.T) {
	got := selectionSummary([]string{"1", "2", "3", "4", "5", "6"})
	for _, want := range []string{"6 item(s)", "1", "5", "... and 1 more"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "\r\n6") {
		t.Fatalf("summary should not include sixth path directly: %q", got)
	}
}

func TestFormatEntryDisplayIncludesMetadata(t *testing.T) {
	mtime := int64(1700000000)
	expectedDate := time.Unix(mtime, 0).Format("2006-01-02")
	got := formatEntryDisplay("file.txt", false, 1536, mtime, "-rw-r--r--", "alice", "staff")
	for _, want := range []string{"file.txt", "1.5 KB", expectedDate} {
		if !strings.Contains(got, want) {
			t.Fatalf("display %q missing %q", got, want)
		}
	}
	if !strings.Contains(got, "-rw-r--r-- alice:staff") {
		t.Fatalf("display %q missing owner metadata", got)
	}
	dir := formatEntryDisplay("folder", true, -1, mtime, "", "", "")
	for _, want := range []string{"folder/", "<DIR>", expectedDate} {
		if !strings.Contains(dir, want) {
			t.Fatalf("display %q missing %q", dir, want)
		}
	}
	if strings.Contains(dir, "?") {
		t.Fatalf("directory display should not show unknown size: %q", dir)
	}
	unknown := formatEntryDisplay("unknown.txt", false, -1, -1, "", "", "")
	if strings.Count(unknown, "?") < 2 {
		t.Fatalf("unknown display should show size and mtime placeholders: %q", unknown)
	}
}

func TestFormatOwnerMode(t *testing.T) {
	tests := []struct {
		name  string
		mode  string
		user  string
		group string
		want  string
	}{
		{name: "all", mode: "-rw-r--r--", user: "alice", group: "staff", want: "-rw-r--r-- alice:staff"},
		{name: "mode only", mode: "-rw-r--r--", want: "-rw-r--r--"},
		{name: "user only", user: "alice", want: "alice"},
		{name: "group only", group: "staff", want: "staff"},
		{name: "empty", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatOwnerMode(tt.mode, tt.user, tt.group); got != tt.want {
				t.Fatalf("unexpected owner mode: got %q want %q", got, tt.want)
			}
		})
	}
}

type fakeDropFileInfo struct {
	name  string
	isDir bool
}

func (f fakeDropFileInfo) Name() string       { return f.name }
func (f fakeDropFileInfo) Size() int64        { return 0 }
func (f fakeDropFileInfo) Mode() os.FileMode  { return 0 }
func (f fakeDropFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeDropFileInfo) IsDir() bool        { return f.isDir }
func (f fakeDropFileInfo) Sys() interface{}   { return nil }

func fakeDropStat(paths map[string]bool) statFunc {
	return func(path string) (os.FileInfo, error) {
		isDir, ok := paths[path]
		if !ok {
			return nil, errors.New("not found")
		}
		return fakeDropFileInfo{name: path, isDir: isDir}, nil
	}
}

func TestShellQuoteCoversSpecialPaths(t *testing.T) {
	got := shellQuote("a b ' c $HOME `x` 中文")
	for _, want := range []string{"'a b '", `'"'"'`, "$HOME", "`x`", "中文"} {
		if !strings.Contains(got, want) {
			t.Fatalf("quote %q missing %q", got, want)
		}
	}
}
