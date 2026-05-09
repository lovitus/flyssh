package wingui

import (
	"reflect"
	"strings"
	"testing"
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
			wantRaw:  `-a 'C:\src' '/tmp/out'`,
		},
		{
			name: "rsync download adds archive", protocol: "rsync", upload: false,
			sources: []string{"/tmp/src"}, target: `C:\out`,
			wantFlag: "--rsync-download",
			wantRaw:  `-a '/tmp/src' 'C:\out'`,
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

func TestShellQuoteCoversSpecialPaths(t *testing.T) {
	got := shellQuote("a b ' c $HOME `x` 中文")
	for _, want := range []string{"'a b '", `'"'"'`, "$HOME", "`x`", "中文"} {
		if !strings.Contains(got, want) {
			t.Fatalf("quote %q missing %q", got, want)
		}
	}
}
