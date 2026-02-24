package config

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/flyssh/flyssh/pkg/cli"
)

// ResolvedConfig is the final resolved SSH configuration for a connection.
type ResolvedConfig struct {
	User                  string
	Hostname              string
	Port                  int
	IdentityFiles         []string
	ConnectTimeout        time.Duration
	ProxyJump             string
	ProxyCommand          string
	SendEnv               []string
	ForwardAgent          bool
	Compression           bool
	ServerAliveInterval   int
	ServerAliveCountMax   int
	StrictHostKeyChecking string

	// SOCKS5 proxy settings
	SocksProxy    string
	SocksUser     string
	SocksPassword string

	// Known hosts file
	KnownHostsFile string

	// Ciphers and MACs
	Ciphers []string
	MACs    []string
}

// SSHConfigEntry represents a parsed Host block from ssh config
type SSHConfigEntry struct {
	Patterns              []string
	Hostname              string
	User                  string
	Port                  int
	IdentityFiles         []string
	ProxyJump             string
	ProxyCommand          string
	ForwardAgent          string
	Compression           string
	ConnectTimeout        int
	ServerAliveInterval   int
	ServerAliveCountMax   int
	StrictHostKeyChecking string
	SendEnv               []string
	KnownHostsFile        string
	Ciphers               string
	MACs                  string
}

// LoadSSHConfig resolves the final configuration from CLI options and ssh config file
func LoadSSHConfig(opts *cli.Options) *ResolvedConfig {
	cfg := &ResolvedConfig{
		Port:                22,
		ConnectTimeout:      30 * time.Second,
		ForwardAgent:        opts.ForwardAgent,
		Compression:         opts.Compression,
		SocksProxy:          opts.SocksProxy,
		SocksUser:           opts.SocksUser,
		SocksPassword:       opts.SocksPassword,
		ServerAliveCountMax: 3,
	}

	// Determine user
	cfg.User = opts.User
	cfg.Hostname = opts.Host

	// Parse SSH config
	configFiles := []string{}
	if opts.ConfigFile != "" {
		configFiles = append(configFiles, opts.ConfigFile)
	} else {
		home := userHomeDir()
		configFiles = append(configFiles, filepath.Join(home, ".ssh", "config"))
		if runtime.GOOS != "windows" {
			configFiles = append(configFiles, "/etc/ssh/ssh_config")
		}
	}

	var entries []SSHConfigEntry
	for _, cf := range configFiles {
		e, err := parseSSHConfig(cf)
		if err != nil {
			continue
		}
		entries = append(entries, e...)
	}

	// Apply matching config entries
	for _, entry := range entries {
		if matchesHost(opts.Host, entry.Patterns) {
			applyEntry(cfg, &entry)
		}
	}

	// CLI overrides
	if opts.Port > 0 {
		cfg.Port = opts.Port
	}
	if opts.User != "" {
		cfg.User = opts.User
	}
	if len(opts.IdentityFiles) > 0 {
		cfg.IdentityFiles = append(opts.IdentityFiles, cfg.IdentityFiles...)
	}
	if opts.ProxyJump != "" {
		cfg.ProxyJump = opts.ProxyJump
	}
	if opts.NoForwardAgent {
		cfg.ForwardAgent = false
	}

	// Apply -o options
	for k, v := range opts.SSHOptions {
		applyOption(cfg, k, v)
	}

	// Default identity files
	if len(cfg.IdentityFiles) == 0 {
		home := userHomeDir()
		cfg.IdentityFiles = []string{
			filepath.Join(home, ".ssh", "id_rsa"),
			filepath.Join(home, ".ssh", "id_ecdsa"),
			filepath.Join(home, ".ssh", "id_ed25519"),
			filepath.Join(home, ".ssh", "id_dsa"),
		}
	}

	// Default user
	if cfg.User == "" {
		cfg.User = currentUsername()
	}

	// Default known hosts
	if cfg.KnownHostsFile == "" {
		home := userHomeDir()
		cfg.KnownHostsFile = filepath.Join(home, ".ssh", "known_hosts")
	}

	return cfg
}

func applyEntry(cfg *ResolvedConfig, e *SSHConfigEntry) {
	if e.Hostname != "" && cfg.Hostname == "" {
		cfg.Hostname = e.Hostname
	}
	// Hostname in config can also remap the actual target
	if e.Hostname != "" {
		cfg.Hostname = e.Hostname
	}
	if e.User != "" && cfg.User == "" {
		cfg.User = e.User
	}
	if e.Port > 0 && cfg.Port == 22 {
		cfg.Port = e.Port
	}
	if len(e.IdentityFiles) > 0 {
		cfg.IdentityFiles = append(cfg.IdentityFiles, expandIdentityFiles(e.IdentityFiles)...)
	}
	if e.ProxyJump != "" && cfg.ProxyJump == "" {
		cfg.ProxyJump = e.ProxyJump
	}
	if e.ProxyCommand != "" && cfg.ProxyCommand == "" {
		cfg.ProxyCommand = e.ProxyCommand
	}
	if e.ForwardAgent == "yes" {
		cfg.ForwardAgent = true
	}
	if e.Compression == "yes" {
		cfg.Compression = true
	}
	if e.ConnectTimeout > 0 {
		cfg.ConnectTimeout = time.Duration(e.ConnectTimeout) * time.Second
	}
	if e.ServerAliveInterval > 0 {
		cfg.ServerAliveInterval = e.ServerAliveInterval
	}
	if e.ServerAliveCountMax > 0 {
		cfg.ServerAliveCountMax = e.ServerAliveCountMax
	}
	if e.StrictHostKeyChecking != "" {
		cfg.StrictHostKeyChecking = e.StrictHostKeyChecking
	}
	if e.KnownHostsFile != "" {
		cfg.KnownHostsFile = e.KnownHostsFile
	}
}

func applyOption(cfg *ResolvedConfig, key, value string) {
	switch strings.ToLower(key) {
	case "hostname":
		cfg.Hostname = value
	case "user":
		if cfg.User == "" {
			cfg.User = value
		}
	case "port":
		if p, err := strconv.Atoi(value); err == nil {
			cfg.Port = p
		}
	case "identityfile":
		cfg.IdentityFiles = append(cfg.IdentityFiles, expandPath(value))
	case "proxyjump":
		cfg.ProxyJump = value
	case "proxycommand":
		cfg.ProxyCommand = value
	case "forwardagent":
		cfg.ForwardAgent = strings.EqualFold(value, "yes")
	case "compression":
		cfg.Compression = strings.EqualFold(value, "yes")
	case "connecttimeout":
		if t, err := strconv.Atoi(value); err == nil {
			cfg.ConnectTimeout = time.Duration(t) * time.Second
		}
	case "serveraliveinterval":
		if t, err := strconv.Atoi(value); err == nil {
			cfg.ServerAliveInterval = t
		}
	case "serveralivecountmax":
		if t, err := strconv.Atoi(value); err == nil {
			cfg.ServerAliveCountMax = t
		}
	case "stricthostkeychecking":
		cfg.StrictHostKeyChecking = value
	case "userknownhostsfile":
		cfg.KnownHostsFile = expandPath(value)
	}
}

func parseSSHConfig(path string) ([]SSHConfigEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []SSHConfigEntry
	var current *SSHConfigEntry

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split key value
		key, value := splitConfigLine(line)
		if key == "" {
			continue
		}

		if strings.EqualFold(key, "Host") {
			if current != nil {
				entries = append(entries, *current)
			}
			current = &SSHConfigEntry{
				Patterns: strings.Fields(value),
			}
			continue
		}

		if strings.EqualFold(key, "Match") {
			// Basic Match support - save current and start new
			if current != nil {
				entries = append(entries, *current)
			}
			current = nil
			continue
		}

		if current == nil {
			// Global options - create a wildcard entry
			current = &SSHConfigEntry{Patterns: []string{"*"}}
		}

		switch strings.ToLower(key) {
		case "hostname":
			current.Hostname = value
		case "user":
			current.User = value
		case "port":
			if p, err := strconv.Atoi(value); err == nil {
				current.Port = p
			}
		case "identityfile":
			current.IdentityFiles = append(current.IdentityFiles, value)
		case "proxyjump":
			current.ProxyJump = value
		case "proxycommand":
			current.ProxyCommand = value
		case "forwardagent":
			current.ForwardAgent = value
		case "compression":
			current.Compression = value
		case "connecttimeout":
			if t, err := strconv.Atoi(value); err == nil {
				current.ConnectTimeout = t
			}
		case "serveraliveinterval":
			if t, err := strconv.Atoi(value); err == nil {
				current.ServerAliveInterval = t
			}
		case "serveralivecountmax":
			if t, err := strconv.Atoi(value); err == nil {
				current.ServerAliveCountMax = t
			}
		case "stricthostkeychecking":
			current.StrictHostKeyChecking = value
		case "sendenv":
			current.SendEnv = append(current.SendEnv, strings.Fields(value)...)
		case "userknownhostsfile":
			current.KnownHostsFile = expandPath(value)
		case "ciphers":
			current.Ciphers = value
		case "macs":
			current.MACs = value
		}
	}

	if current != nil {
		entries = append(entries, *current)
	}

	return entries, scanner.Err()
}

func splitConfigLine(line string) (string, string) {
	// SSH config allows both "Key Value" and "Key=Value"
	if idx := strings.Index(line, "="); idx != -1 {
		return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])
	}
	fields := strings.SplitN(line, " ", 2)
	if len(fields) != 2 {
		fields = strings.SplitN(line, "\t", 2)
	}
	if len(fields) == 2 {
		return strings.TrimSpace(fields[0]), strings.TrimSpace(fields[1])
	}
	return "", ""
}

func matchesHost(host string, patterns []string) bool {
	for _, pat := range patterns {
		if pat == "*" {
			return true
		}
		if matchGlob(pat, host) {
			return true
		}
	}
	return false
}

func matchGlob(pattern, name string) bool {
	matched, _ := filepath.Match(pattern, name)
	return matched
}

func expandIdentityFiles(files []string) []string {
	var result []string
	for _, f := range files {
		result = append(result, expandPath(f))
	}
	return result
}

func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~\\") {
		return filepath.Join(userHomeDir(), p[2:])
	}
	return p
}

func userHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

func currentUsername() string {
	// Try common env vars
	for _, env := range []string{"USER", "USERNAME", "LOGNAME"} {
		if u := os.Getenv(env); u != "" {
			return u
		}
	}
	return "user"
}
