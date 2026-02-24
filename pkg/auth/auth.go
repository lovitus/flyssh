package auth

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/flyssh/flyssh/pkg/cli"
	"github.com/flyssh/flyssh/pkg/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

// BuildAuthMethods constructs SSH auth methods from config and options
func BuildAuthMethods(cfg *config.ResolvedConfig, opts *cli.Options) ([]ssh.AuthMethod, error) {
	return buildAuthMethodsWithPassword(cfg, opts, opts.Password)
}

// BuildAuthMethodsForSecondHost constructs auth methods for the second hop
func BuildAuthMethodsForSecondHost(cfg *config.ResolvedConfig, opts *cli.Options) ([]ssh.AuthMethod, error) {
	return buildAuthMethodsWithPassword(cfg, opts, opts.SecondHostPassword)
}

// BuildAuthMethodsForHop constructs auth methods for an arbitrary hop with an explicit password.
func BuildAuthMethodsForHop(cfg *config.ResolvedConfig, opts *cli.Options, password string) ([]ssh.AuthMethod, error) {
	return buildAuthMethodsWithPassword(cfg, opts, password)
}

func buildAuthMethodsWithPassword(cfg *config.ResolvedConfig, opts *cli.Options, password string) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	// 1. If explicit password is provided, prioritize it
	if password != "" {
		methods = append(methods, ssh.Password(password))
		// Also handle keyboard-interactive with the known password
		pw := password
		methods = append(methods, ssh.KeyboardInteractive(
			func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = pw
				}
				return answers, nil
			}))
		if opts.Verbose {
			log.Println("Auth: using provided password")
		}
	}

	// 2. SSH Agent
	if agentAuth := getAgentAuth(); agentAuth != nil {
		methods = append(methods, agentAuth)
		if opts.Verbose {
			log.Println("Auth: added SSH agent")
		}
	}

	// 3. Public key files
	var signers []ssh.Signer
	for _, keyPath := range cfg.IdentityFiles {
		signer, err := loadPrivateKey(keyPath, opts)
		if err != nil {
			if opts.Verbose {
				log.Printf("Auth: skip key %s: %v", keyPath, err)
			}
			continue
		}
		signers = append(signers, signer)
		if opts.Verbose {
			log.Printf("Auth: loaded key %s", keyPath)
		}
	}
	if len(signers) > 0 {
		methods = append(methods, ssh.PublicKeys(signers...))
	}

	// 4. If no explicit password, add interactive methods
	if password == "" {
		methods = append(methods, ssh.KeyboardInteractive(keyboardInteractiveChallenge))
		methods = append(methods, ssh.PasswordCallback(func() (string, error) {
			fmt.Fprintf(os.Stderr, "%s@%s's password: ", cfg.User, cfg.Hostname)
			pass, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return "", err
			}
			return string(pass), nil
		}))
	}

	return methods, nil
}

// GetHostKeyCallback returns an appropriate host key callback.
// Default: auto-accept new fingerprints (like StrictHostKeyChecking=accept-new),
// but warn and block if an existing key changes (possible MITM).
// mode "no" = accept everything; mode "ask" = classic OpenSSH yes/no; mode "yes" = reject unknown.
func GetHostKeyCallback(cfg *config.ResolvedConfig, opts *cli.Options) ssh.HostKeyCallback {
	mode := strings.ToLower(cfg.StrictHostKeyChecking)

	if mode == "no" {
		return ssh.InsecureIgnoreHostKey()
	}

	autoAcceptNew := mode != "ask"

	knownHostsFile := resolveKnownHostsFile(cfg)

	if knownHostsFile != "" {
		ensureKnownHostsFile(knownHostsFile)
		hostKeyCallback, err := knownhosts.New(knownHostsFile)
		if err == nil {
			return autoAcceptHostKeyCallback(hostKeyCallback, knownHostsFile, opts, autoAcceptNew)
		}
		if opts.Verbose {
			log.Printf("Warning: could not parse known_hosts: %v", err)
		}
	}

	if mode == "yes" {
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return fmt.Errorf("host key verification failed: no known_hosts file")
		}
	}

	// Fallback: no known_hosts file available
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)
		if autoAcceptNew {
			fmt.Fprintf(os.Stderr, "Auto-accepting host key for %s (%s): %s %s\n",
				hostname, remote.String(), key.Type(), fingerprint)
			if knownHostsFile != "" {
				saveHostKey(knownHostsFile, hostname, key)
			}
			return nil
		}
		fmt.Fprintf(os.Stderr, "The authenticity of host '%s (%s)' can't be established.\n",
			hostname, remote.String())
		fmt.Fprintf(os.Stderr, "%s key fingerprint is %s.\n", key.Type(), fingerprint)
		fmt.Fprintf(os.Stderr, "Are you sure you want to continue connecting (yes/no)? ")
		var answer string
		fmt.Fscanln(os.Stdin, &answer)
		if strings.ToLower(strings.TrimSpace(answer)) == "yes" {
			if knownHostsFile != "" {
				saveHostKey(knownHostsFile, hostname, key)
			}
			return nil
		}
		return fmt.Errorf("host key verification failed")
	}
}

func resolveKnownHostsFile(cfg *config.ResolvedConfig) string {
	if cfg.KnownHostsFile != "" {
		return cfg.KnownHostsFile
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		return filepath.Join(home, ".ssh", "known_hosts")
	}
	return ""
}

func ensureKnownHostsFile(path string) {
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0700)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			f.Close()
		}
	}
}

// autoAcceptHostKeyCallback wraps knownhosts callback with auto-accept/confirm logic.
func autoAcceptHostKeyCallback(cb ssh.HostKeyCallback, knownHostsFile string, opts *cli.Options, autoAcceptNew bool) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := cb(hostname, remote, key)
		if err == nil {
			return nil
		}

		fingerprint := ssh.FingerprintSHA256(key)
		var keyErr *knownhosts.KeyError
		if isKeyError(err, &keyErr) {
			if len(keyErr.Want) > 0 {
				// KEY CHANGED — always require explicit confirmation
				fmt.Fprintf(os.Stderr, "\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n")
				fmt.Fprintf(os.Stderr, "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n")
				fmt.Fprintf(os.Stderr, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n")
				fmt.Fprintf(os.Stderr, "Host: %s (%s)\n", hostname, remote.String())
				fmt.Fprintf(os.Stderr, "New %s key fingerprint: %s\n", key.Type(), fingerprint)
				fmt.Fprintf(os.Stderr, "\nTo accept the new key, type exactly: confirm fingerprint changed\n")
				fmt.Fprintf(os.Stderr, "> ")

				reader := bufio.NewReader(os.Stdin)
				line, _ := reader.ReadString('\n')
				line = strings.TrimSpace(line)

				if line == "confirm fingerprint changed" {
					// Remove old key and save new one
					removeHostKey(knownHostsFile, hostname)
					saveHostKey(knownHostsFile, hostname, key)
					fmt.Fprintf(os.Stderr, "Host key for %s updated.\n", hostname)
					return nil
				}
				return fmt.Errorf("host key verification failed: fingerprint changed and not confirmed")
			}

			// NEW HOST — not in known_hosts
			if autoAcceptNew {
				fmt.Fprintf(os.Stderr, "Auto-accepting new host key for %s (%s): %s %s\n",
					hostname, remote.String(), key.Type(), fingerprint)
				saveHostKey(knownHostsFile, hostname, key)
				return nil
			}

			// Interactive: ask user
			fmt.Fprintf(os.Stderr, "The authenticity of host '%s (%s)' can't be established.\n",
				hostname, remote.String())
			fmt.Fprintf(os.Stderr, "%s key fingerprint is %s.\n", key.Type(), fingerprint)
			fmt.Fprintf(os.Stderr, "Are you sure you want to continue connecting (yes/no)? ")
			var answer string
			fmt.Fscanln(os.Stdin, &answer)
			if strings.ToLower(strings.TrimSpace(answer)) == "yes" {
				saveHostKey(knownHostsFile, hostname, key)
				return nil
			}
			return fmt.Errorf("host key verification failed")
		}

		return err
	}
}

func isKeyError(err error, target **knownhosts.KeyError) bool {
	if keyErr, ok := err.(*knownhosts.KeyError); ok {
		*target = keyErr
		return true
	}
	return false
}

func saveHostKey(path, hostname string, key ssh.PublicKey) {
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0700)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	line := knownhosts.Line([]string{hostname}, key)
	fmt.Fprintf(f, "%s\n", line)
}

// removeHostKey removes all lines matching hostname from known_hosts
func removeHostKey(path, hostname string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	// Normalize hostname for comparison (knownhosts uses [host]:port format)
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			lines = append(lines, line)
			continue
		}
		// Check if this line starts with the hostname
		fields := strings.Fields(trimmed)
		if len(fields) >= 1 {
			hosts := strings.Split(fields[0], ",")
			match := false
			for _, h := range hosts {
				if h == hostname || strings.HasPrefix(h, hostname+" ") {
					match = true
					break
				}
			}
			if match {
				continue // skip this line
			}
		}
		lines = append(lines, line)
	}

	os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0600)
}

func getAgentAuth() ssh.AuthMethod {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil
	}

	agentClient := agent.NewClient(conn)
	return ssh.PublicKeysCallback(agentClient.Signers)
}

func loadPrivateKey(path string, opts *cli.Options) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Try without passphrase first
	signer, err := ssh.ParsePrivateKey(data)
	if err == nil {
		return signer, nil
	}

	// Check if it's a passphrase error
	if _, ok := err.(*ssh.PassphraseMissingError); ok {
		fmt.Fprintf(os.Stderr, "Enter passphrase for key '%s': ", path)
		passphrase, err2 := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err2 != nil {
			return nil, err2
		}
		return ssh.ParsePrivateKeyWithPassphrase(data, passphrase)
	}

	return nil, err
}

func keyboardInteractiveChallenge(name, instruction string, questions []string, echos []bool) ([]string, error) {
	if name != "" {
		fmt.Fprintln(os.Stderr, name)
	}
	if instruction != "" {
		fmt.Fprintln(os.Stderr, instruction)
	}

	answers := make([]string, len(questions))
	for i, q := range questions {
		fmt.Fprint(os.Stderr, q)
		if echos[i] {
			var answer string
			fmt.Fscanln(os.Stdin, &answer)
			answers[i] = answer
		} else {
			pass, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return nil, err
			}
			answers[i] = string(pass)
		}
	}
	return answers, nil
}
