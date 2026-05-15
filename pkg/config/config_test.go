package config

import (
	"os"
	"path/filepath"
	"reflect"
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

func TestApplyOption_CiphersAndMACsOverrideConfig(t *testing.T) {
	cfgFile := writeSSHConfig(t, `
Host myhost
    Ciphers aes128-cbc,aes192-cbc
    MACs hmac-sha1,hmac-md5
`)

	opts := &cli.Options{
		Host:       "myhost",
		ConfigFile: cfgFile,
		SSHOptions: map[string]string{
			"Ciphers": "aes256-ctr, chacha20-poly1305@openssh.com",
			"MACs":    "hmac-sha2-256, hmac-sha2-512",
		},
	}
	cfg := LoadSSHConfig(opts)

	wantCiphers := []string{"aes256-ctr", "chacha20-poly1305@openssh.com"}
	if !reflect.DeepEqual(cfg.Ciphers, wantCiphers) {
		t.Fatalf("expected CLI -o Ciphers override, got %#v", cfg.Ciphers)
	}
	wantMACs := []string{"hmac-sha2-256", "hmac-sha2-512"}
	if !reflect.DeepEqual(cfg.MACs, wantMACs) {
		t.Fatalf("expected CLI -o MACs override, got %#v", cfg.MACs)
	}
}

func TestCLIShortCiphersAndMACsOverrideConfig(t *testing.T) {
	cfgFile := writeSSHConfig(t, `
Host myhost
    Ciphers aes128-cbc,aes192-cbc
    MACs hmac-sha1,hmac-md5
`)

	opts := &cli.Options{
		Host:       "myhost",
		ConfigFile: cfgFile,
		CipherSpec: "aes256-ctr, chacha20-poly1305@openssh.com",
		MACSpec:    "hmac-sha2-256, hmac-sha2-512",
	}
	cfg := LoadSSHConfig(opts)

	wantCiphers := []string{"aes256-ctr", "chacha20-poly1305@openssh.com"}
	if !reflect.DeepEqual(cfg.Ciphers, wantCiphers) {
		t.Fatalf("expected -c Ciphers override, got %#v", cfg.Ciphers)
	}
	wantMACs := []string{"hmac-sha2-256", "hmac-sha2-512"}
	if !reflect.DeepEqual(cfg.MACs, wantMACs) {
		t.Fatalf("expected -m MACs override, got %#v", cfg.MACs)
	}
}

func TestApplyOption_CiphersAndMACsOverrideShortFlags(t *testing.T) {
	opts := &cli.Options{
		Host:       "myhost",
		CipherSpec: "aes128-cbc",
		MACSpec:    "hmac-sha1",
		SSHOptions: map[string]string{
			"Ciphers": "aes256-ctr",
			"MACs":    "hmac-sha2-256",
		},
	}
	cfg := LoadSSHConfig(opts)

	if want := []string{"aes256-ctr"}; !reflect.DeepEqual(cfg.Ciphers, want) {
		t.Fatalf("expected -o Ciphers to override -c, got %#v", cfg.Ciphers)
	}
	if want := []string{"hmac-sha2-256"}; !reflect.DeepEqual(cfg.MACs, want) {
		t.Fatalf("expected -o MACs to override -m, got %#v", cfg.MACs)
	}
}
