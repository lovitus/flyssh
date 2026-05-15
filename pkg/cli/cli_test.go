package cli

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestParseArgs_TransferFlag(t *testing.T) {
	opts, err := ParseArgs([]string{"user@host", "--rsync-upload", "-avzhP ./src/ /dst/"})
	if err != nil {
		t.Fatalf("ParseArgs returned error: %v", err)
	}
	if opts.Host != "host" {
		t.Fatalf("unexpected host: %q", opts.Host)
	}
	if opts.User != "user" {
		t.Fatalf("unexpected user: %q", opts.User)
	}
	if opts.RsyncUpload != "-avzhP ./src/ /dst/" {
		t.Fatalf("unexpected rsync upload block: %q", opts.RsyncUpload)
	}
}

func TestParseArgs_CommandSeparatorAllowsAtSignInCommand(t *testing.T) {
	opts, err := ParseArgs([]string{"jump@host1", "user@host2", "--", `printf '%s\n' 'a@b'`})
	if err != nil {
		t.Fatalf("ParseArgs returned error: %v", err)
	}
	if opts.Host != "host1" || len(opts.ExtraHosts) != 1 || opts.ExtraHosts[0] != "user@host2" {
		t.Fatalf("unexpected route: host=%q extra=%#v", opts.Host, opts.ExtraHosts)
	}
	if want := `printf '%s\n' 'a@b'`; opts.Command != want {
		t.Fatalf("unexpected command: got %q want %q", opts.Command, want)
	}
}

func TestParseArgs_CommandSeparatorRequiresHost(t *testing.T) {
	_, err := ParseArgs([]string{"--", "echo ok"})
	if err == nil {
		t.Fatal("expected command separator without host to fail")
	}
	if !strings.Contains(err.Error(), "requires a host") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseArgs_WinguiFlag(t *testing.T) {
	opts, err := ParseArgs([]string{"user@host", "--wingui"})
	if err != nil {
		t.Fatalf("ParseArgs returned error: %v", err)
	}
	if !opts.Wingui {
		t.Fatal("expected Wingui")
	}
	if opts.Host != "host" || opts.User != "user" {
		t.Fatalf("unexpected host parse: %+v", opts)
	}
}

func TestParseArgs_WinguiRejectsConflicts(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"transfer", []string{"user@host", "--wingui", "--scp-upload", "./a /b"}, "transfer flags"},
		{"command", []string{"user@host", "--wingui", "uname"}, "remote command"},
		{"no command", []string{"user@host", "--wingui", "-N"}, "-N"},
		{"stdio", []string{"user@host", "--wingui", "-W", "127.0.0.1:80"}, "-W"},
		{"local forward", []string{"user@host", "--wingui", "-L", "8080:127.0.0.1:80"}, "port forwarding"},
		{"remote forward", []string{"user@host", "--wingui", "-R", "8080:127.0.0.1:80"}, "port forwarding"},
		{"dynamic forward", []string{"user@host", "--wingui", "-D", "1080"}, "port forwarding"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseArgs(tt.args)
			if err == nil {
				t.Fatal("expected conflict error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseArgs_GUIInternalFlags(t *testing.T) {
	opts, err := ParseArgs([]string{"user@host", "--gui-internal-list", "/tmp/a b"})
	if err != nil {
		t.Fatalf("ParseArgs returned error: %v", err)
	}
	if opts.GuiInternalList != "/tmp/a b" {
		t.Fatalf("unexpected list dir: %q", opts.GuiInternalList)
	}
	if !opts.HasGUIInternalMode() {
		t.Fatal("expected GUI internal mode")
	}

	opts, err = ParseArgs([]string{"user@host", "--gui-internal-home"})
	if err != nil {
		t.Fatalf("ParseArgs returned error: %v", err)
	}
	if !opts.GuiInternalHome {
		t.Fatal("expected GuiInternalHome")
	}
}

func TestParseArgs_SSHGatewayRejectsGUIInternalFlags(t *testing.T) {
	_, err := ParseArgs([]string{
		"user@host",
		"--ssh-gateway", "admin:secret@127.0.0.1:2222",
		"--gui-internal-home",
	})
	if err == nil {
		t.Fatal("expected --ssh-gateway with GUI internal mode to fail")
	}
	if !strings.Contains(err.Error(), "GUI internal") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrintUsage_HidesGUIInternalFlags(t *testing.T) {
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	PrintUsage()
	_ = w.Close()
	os.Stderr = oldStderr
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read usage: %v", err)
	}
	text := string(out)
	if strings.Contains(text, "--gui-internal") {
		t.Fatalf("usage exposes hidden internal flags:\n%s", text)
	}
	if !strings.Contains(text, "--wingui") {
		t.Fatalf("usage does not mention --wingui:\n%s", text)
	}
	for _, want := range []string{"--ssh-gateway", "--help", "--version"} {
		if !strings.Contains(text, want) {
			t.Fatalf("usage does not mention %s:\n%s", want, text)
		}
	}
	if strings.Contains(text, "--key FILE") {
		t.Fatalf("usage exposes unsupported --key flag:\n%s", text)
	}
}

func TestParseArgs_TransferFlagsMutuallyExclusive(t *testing.T) {
	_, err := ParseArgs([]string{"user@host", "--rsync-upload", "./a /b", "--scp-upload", "./c /d"})
	if err == nil {
		t.Fatal("expected mutual exclusion error")
	}
	if err.Error() != "transfer flags are mutually exclusive" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseArgs_TransferFlagRejectsRemoteCommand(t *testing.T) {
	_, err := ParseArgs([]string{"user@host", "--scp-upload", "./a /b", "uname", "-a"})
	if err == nil {
		t.Fatal("expected conflict error")
	}
	if err.Error() != "transfer mode cannot be combined with a remote command" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseArgs_TransferFlagRejectsNoCommand(t *testing.T) {
	_, err := ParseArgs([]string{"user@host", "-N", "--scp-upload", "./a /b"})
	if err == nil {
		t.Fatal("expected conflict error")
	}
	if err.Error() != "transfer mode cannot be combined with -N" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseArgs_TransferFlagRejectsForwarding(t *testing.T) {
	tests := [][]string{
		{"user@host", "-L", "8080:127.0.0.1:80", "--scp-upload", "./a /b"},
		{"user@host", "-R", "8080:127.0.0.1:80", "--scp-upload", "./a /b"},
		{"user@host", "-D", "1080", "--scp-upload", "./a /b"},
		{"user@host", "-W", "127.0.0.1:80", "--scp-upload", "./a /b"},
	}

	for _, args := range tests {
		_, err := ParseArgs(args)
		if err == nil {
			t.Fatalf("expected conflict error for args %#v", args)
		}
		if !strings.Contains(err.Error(), "transfer mode cannot be combined") {
			t.Fatalf("unexpected error for args %#v: %v", args, err)
		}
	}
}
