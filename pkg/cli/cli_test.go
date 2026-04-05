package cli

import (
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
