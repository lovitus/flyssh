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

func TestParseArgs_MoshFlag(t *testing.T) {
	opts, err := ParseArgs([]string{"user@host", "--mosh", "--mosh-session", "work_1"})
	if err != nil {
		t.Fatalf("ParseArgs returned error: %v", err)
	}
	if !opts.Mosh || opts.MoshSession != "work_1" {
		t.Fatalf("unexpected mosh options: %+v", opts)
	}
}

func TestParseArgs_MoshRejectsConflicts(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"command", []string{"user@host", "--mosh", "uname"}, "remote command"},
		{"transfer", []string{"user@host", "--mosh", "--scp-upload", "a b"}, "transfer flags"},
		{"wingui", []string{"user@host", "--mosh", "--wingui"}, "--wingui"},
		{"gateway", []string{"user@host", "--mosh", "--ssh-gateway", "u:p@127.0.0.1:2222"}, "--ssh-gateway"},
		{"forward", []string{"user@host", "--mosh", "-L", "8080:127.0.0.1:80"}, "port forwarding"},
		{"agent", []string{"user@host", "--mosh", "-A"}, "-A"},
		{"x11", []string{"user@host", "--mosh", "-X"}, "-X"},
		{"subsystem", []string{"user@host", "--mosh", "-s"}, "-s"},
		{"tty", []string{"user@host", "--mosh", "-T"}, "-T"},
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

func TestValidateMoshSessionName(t *testing.T) {
	for _, name := range []string{"work", "a.b_c-1", "-dash"} {
		if err := ValidateMoshSessionName(name); err != nil {
			t.Fatalf("%q should be valid: %v", name, err)
		}
	}
	for _, name := range []string{"", ".", "..", "a/b", "a\\b", "~", "a b", "中文"} {
		if err := ValidateMoshSessionName(name); err == nil {
			t.Fatalf("%q should be invalid", name)
		}
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
	for _, want := range []string{"--ssh-gateway", "--mosh", "--mosh-session", "--help", "--version"} {
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

func TestParseArgs_RelayPolicy(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want RelayPolicy
	}{
		{"equals auto", []string{"user@host", "--relay=auto", "-L", "8080:127.0.0.1:80"}, RelayPolicyAuto},
		{"equals disable", []string{"user@host", "--relay=disable", "-R", "8080:127.0.0.1:80"}, RelayPolicyDisable},
		{"space prefer", []string{"user@host", "--relay", "prefer", "-D", "1080"}, RelayPolicyPrefer},
		{"disable alias", []string{"user@host", "--disable-relay", "-L", "8080:127.0.0.1:80"}, RelayPolicyDisable},
		{"prefer alias", []string{"user@host", "--prefer-relay", "-R", "8080:127.0.0.1:80"}, RelayPolicyPrefer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := ParseArgs(tt.args)
			if err != nil {
				t.Fatalf("ParseArgs returned error: %v", err)
			}
			if opts.RelayPolicy != tt.want {
				t.Fatalf("global policy: got %q want %q", opts.RelayPolicy, tt.want)
			}
			for _, forwards := range [][]ForwardSpec{opts.LocalForwards, opts.RemoteForwards, opts.DynamicForwards} {
				for _, forward := range forwards {
					if forward.RelayPolicy != tt.want {
						t.Fatalf("forward policy: got %q want %q in %+v", forward.RelayPolicy, tt.want, forward)
					}
				}
			}
		})
	}
}

func TestParseArgs_RelayPolicyRejectsConflicts(t *testing.T) {
	tests := [][]string{
		{"user@host", "--relay=prefer", "--disable-relay", "-L", "8080:127.0.0.1:80"},
		{"user@host", "--prefer-relay", "--relay=disable", "-R", "8080:127.0.0.1:80"},
		{"user@host", "--disable-relay", "--prefer-relay", "-D", "1080"},
	}
	for _, args := range tests {
		_, err := ParseArgs(args)
		if err == nil {
			t.Fatalf("expected conflict for %#v", args)
		}
		if !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("unexpected error for %#v: %v", args, err)
		}
	}
}

func TestParseArgs_RelayPolicyRequiresForwarding(t *testing.T) {
	_, err := ParseArgs([]string{"user@host", "--relay=prefer"})
	if err == nil {
		t.Fatal("expected relay policy without forwarding to fail")
	}
	if !strings.Contains(err.Error(), "requires port forwarding") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseArgs_EasyForwardRelayQuery(t *testing.T) {
	opts, err := ParseArgs([]string{
		"user@host",
		"--relay=prefer",
		"-ltcp://:8080/remote:80?relay=disable,:8081/remote:81",
		"-rtcp://:3333/:2222?relay=auto",
		"-dynamicproxy://1081?relay=disable",
	})
	if err != nil {
		t.Fatalf("ParseArgs returned error: %v", err)
	}
	if len(opts.LocalForwards) != 2 || len(opts.RemoteForwards) != 1 || len(opts.DynamicForwards) != 1 {
		t.Fatalf("unexpected forwards: local=%+v remote=%+v dynamic=%+v", opts.LocalForwards, opts.RemoteForwards, opts.DynamicForwards)
	}
	if got := opts.LocalForwards[0].RelayPolicy; got != RelayPolicyDisable {
		t.Fatalf("local query policy: got %q want disable", got)
	}
	if got := opts.LocalForwards[1].RelayPolicy; got != RelayPolicyPrefer {
		t.Fatalf("local inherited policy: got %q want prefer", got)
	}
	if got := opts.RemoteForwards[0].RelayPolicy; got != RelayPolicyAuto {
		t.Fatalf("remote query policy: got %q want auto", got)
	}
	if got := opts.DynamicForwards[0].RelayPolicy; got != RelayPolicyDisable {
		t.Fatalf("dynamic query policy: got %q want disable", got)
	}
	if got := opts.LocalForwards[0].Spec; got != "127.0.0.1:8080:remote:80" {
		t.Fatalf("unexpected normalized local spec: %q", got)
	}
	if got := opts.DynamicForwards[0].Spec; got != "127.0.0.1:1081" {
		t.Fatalf("unexpected normalized dynamic spec: %q", got)
	}
}

func TestParseArgs_EasyForwardRejectsUnknownQueryKey(t *testing.T) {
	raw := ":8080/remote:80?relay=prefer&mode=bad"
	_, err := ParseArgs([]string{"user@host", "-ltcp://" + raw})
	if err == nil {
		t.Fatal("expected unknown query key error")
	}
	if !strings.Contains(err.Error(), "mode") || !strings.Contains(err.Error(), raw) {
		t.Fatalf("error should include key and raw entry, got: %v", err)
	}
}
