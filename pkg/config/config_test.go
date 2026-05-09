package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/flyssh/flyssh/pkg/cli"
)

func writeSSHConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write ssh config: %v", err)
	}
	return path
}

// TestApplyEntry_HostnameFirstMatchWins verifies that the first matching Host
// block's Hostname directive wins and later blocks cannot overwrite it.
func TestApplyEntry_HostnameFirstMatchWins(t *testing.T) {
	cfgFile := writeSSHConfig(t, `
Host prod
    Hostname production.internal.example.com

Host *
    Hostname dev.example.com
`)

	opts := &cli.Options{
		Host:       "prod",
		ConfigFile: cfgFile,
	}
	cfg := LoadSSHConfig(opts)

	if cfg.Hostname != "production.internal.example.com" {
		t.Fatalf("expected first-match Hostname, got %q", cfg.Hostname)
	}
}

// TestApplyEntry_HostnameFallsBackToOptHost verifies that when no config entry
// provides a Hostname remapping, cfg.Hostname equals opts.Host.
func TestApplyEntry_HostnameFallsBackToOptHost(t *testing.T) {
	cfgFile := writeSSHConfig(t, `
Host other
    Hostname remapped.example.com
`)

	opts := &cli.Options{
		Host:       "myhost",
		ConfigFile: cfgFile,
	}
	cfg := LoadSSHConfig(opts)

	if cfg.Hostname != "myhost" {
		t.Fatalf("expected opts.Host fallback, got %q", cfg.Hostname)
	}
}

// TestApplyEntry_UserFirstMatchWins verifies existing first-match-wins for User
// is not regressed.
func TestApplyEntry_UserFirstMatchWins(t *testing.T) {
	cfgFile := writeSSHConfig(t, `
Host myhost
    User specific-user

Host *
    User wildcard-user
`)

	opts := &cli.Options{
		Host:       "myhost",
		ConfigFile: cfgFile,
	}
	cfg := LoadSSHConfig(opts)

	if cfg.User != "specific-user" {
		t.Fatalf("expected first-match User, got %q", cfg.User)
	}
}

// TestApplyEntry_CLIHostOverridesConfig verifies that a CLI -o Hostname=...
// (or the post-loop reassignment in resolveHopSSHConfig) still wins over config.
func TestApplyEntry_CLIOptionHostnameOverrides(t *testing.T) {
	cfgFile := writeSSHConfig(t, `
Host myhost
    Hostname config.example.com
`)

	opts := &cli.Options{
		Host:       "myhost",
		ConfigFile: cfgFile,
		SSHOptions: map[string]string{"Hostname": "cli-override.example.com"},
	}
	cfg := LoadSSHConfig(opts)

	if cfg.Hostname != "cli-override.example.com" {
		t.Fatalf("expected CLI -o Hostname override, got %q", cfg.Hostname)
	}
}
