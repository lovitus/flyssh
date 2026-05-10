package wingui

import (
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

func TestFormatEntryDisplayIncludesMetadata(t *testing.T) {
	mtime := int64(1700000000)
	expectedDate := time.Unix(mtime, 0).Format("2006-01-02")
	got := formatEntryDisplay("file.txt", false, 1536, mtime)
	for _, want := range []string{"file.txt", "1.5 KB", expectedDate} {
		if !strings.Contains(got, want) {
			t.Fatalf("display %q missing %q", got, want)
		}
	}
	dir := formatEntryDisplay("folder", true, 0, mtime)
	for _, want := range []string{"folder/", "<DIR>", expectedDate} {
		if !strings.Contains(dir, want) {
			t.Fatalf("display %q missing %q", dir, want)
		}
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
