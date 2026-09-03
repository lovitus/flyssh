package auth

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/flyssh/flyssh/pkg/cli"
	"github.com/flyssh/flyssh/pkg/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

var promptInputOpener = openPromptInput
var localPromptLineReader = readLocalPromptLine
var localPromptPasswordReader = readLocalPromptPassword

// PasswordCache holds passwords entered during one FlySSH process lifetime.
// It deliberately has no persistence: a reconnect may reuse a successful
// terminal prompt, but a later FlySSH invocation starts without these values.
type PasswordCache struct {
	mu       sync.RWMutex
	password map[string]string
}

func NewPasswordCache() *PasswordCache {
	return &PasswordCache{password: make(map[string]string)}
}

func (c *PasswordCache) Get(cfg *config.ResolvedConfig) (string, bool) {
	if c == nil || cfg == nil {
		return "", false
	}
	c.mu.RLock()
	password, ok := c.password[passwordCacheKey(cfg)]
	c.mu.RUnlock()
	return password, ok
}

func (c *PasswordCache) Store(cfg *config.ResolvedConfig, password string) {
	if c == nil || cfg == nil || password == "" {
		return
	}
	c.mu.Lock()
	c.password[passwordCacheKey(cfg)] = password
	c.mu.Unlock()
}

// Forget removes the cached password for cfg and reports whether one existed.
func (c *PasswordCache) Forget(cfg *config.ResolvedConfig) bool {
	if c == nil || cfg == nil {
		return false
	}
	key := passwordCacheKey(cfg)
	c.mu.Lock()
	_, existed := c.password[key]
	delete(c.password, key)
	c.mu.Unlock()
	return existed
}

func passwordCacheKey(cfg *config.ResolvedConfig) string {
	return cfg.User + "@" + strings.ToLower(cfg.Hostname) + ":" + strconv.Itoa(cfg.Port)
}

// BuildAuthMethods constructs SSH auth methods from config and options
func BuildAuthMethods(cfg *config.ResolvedConfig, opts *cli.Options) ([]ssh.AuthMethod, error) {
	return BuildAuthMethodsWithPasswordCache(cfg, opts, nil)
}

// BuildAuthMethodsWithPasswordCache is BuildAuthMethods with an optional
// process-local cache for passwords obtained from an interactive prompt.
func BuildAuthMethodsWithPasswordCache(cfg *config.ResolvedConfig, opts *cli.Options, cache *PasswordCache) ([]ssh.AuthMethod, error) {
	return buildAuthMethodsWithPassword(cfg, opts, opts.Password, cache)
}

// BuildAuthMethodsForSecondHost constructs auth methods for the second hop
func BuildAuthMethodsForSecondHost(cfg *config.ResolvedConfig, opts *cli.Options) ([]ssh.AuthMethod, error) {
	return BuildAuthMethodsForHopWithPasswordCache(cfg, opts, opts.SecondHostPassword, nil)
}

// BuildAuthMethodsForHop constructs auth methods for an arbitrary hop with an explicit password.
func BuildAuthMethodsForHop(cfg *config.ResolvedConfig, opts *cli.Options, password string) ([]ssh.AuthMethod, error) {
	return BuildAuthMethodsForHopWithPasswordCache(cfg, opts, password, nil)
}

// BuildAuthMethodsForHopWithPasswordCache builds auth for an individual hop.
// Explicit hop credentials always win over values cached from a prior prompt.
func BuildAuthMethodsForHopWithPasswordCache(cfg *config.ResolvedConfig, opts *cli.Options, password string, cache *PasswordCache) ([]ssh.AuthMethod, error) {
	return buildAuthMethodsWithPassword(cfg, opts, password, cache)
}

func buildAuthMethodsWithPassword(cfg *config.ResolvedConfig, opts *cli.Options, password string, cache *PasswordCache) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if password == "" {
		if cached, ok := cache.Get(cfg); ok {
			password = cached
		}
	}

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
		methods = append(methods, ssh.KeyboardInteractive(keyboardInteractiveChallengeWithCache(cfg, cache)))
		methods = append(methods, ssh.PasswordCallback(func() (string, error) {
			fmt.Fprintf(os.Stderr, "%s@%s's password: ", cfg.User, cfg.Hostname)
			pass, err := readPromptPassword()
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return "", err
			}
			value := string(pass)
			cache.Store(cfg, value)
			return value, nil
		}))
	}

	return methods, nil
}

// IsAuthenticationFailure identifies the errors returned after a server has
// rejected every offered authentication method. It is intentionally narrow so
// transient network failures do not discard a useful in-memory password.
func IsAuthenticationFailure(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unable to authenticate") ||
		strings.Contains(message, "permission denied") ||
		strings.Contains(message, "authentication failed")
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
		answer, _ := readPromptLine()
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

func openPromptInput() (*os.File, func(), error) {
	device := "/dev/tty"
	if runtime.GOOS == "windows" {
		device = "CONIN$"
	}

	f, err := os.Open(device)
	if err == nil {
		return f, func() { _ = f.Close() }, nil
	}
	if os.Stdin != nil {
		return os.Stdin, func() {}, nil
	}
	return nil, nil, err
}

func readPromptLine() (string, error) {
	if value, ok, err := requestPromptBroker("line"); ok {
		return value, err
	}
	return localPromptLineReader()
}

func readPromptPassword() ([]byte, error) {
	if value, ok, err := requestPromptBroker("password"); ok {
		return []byte(value), err
	}
	return localPromptPasswordReader()
}

func readLocalPromptLine() (string, error) {
	in, closeFn, err := promptInputOpener()
	if err != nil {
		return "", err
	}
	defer closeFn()

	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func readLocalPromptPassword() ([]byte, error) {
	in, closeFn, err := promptInputOpener()
	if err != nil {
		return nil, err
	}
	defer closeFn()
	return term.ReadPassword(int(in.Fd()))
}

// autoAcceptHostKeyCallback wraps knownhosts callback with auto-accept/confirm logic.
func autoAcceptHostKeyCallback(cb ssh.HostKeyCallback, knownHostsFile string, opts *cli.Options, autoAcceptNew bool) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		remote = normalizeRemoteAddr(hostname, remote)
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

				line, _ := readPromptLine()

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
			answer, _ := readPromptLine()
			if strings.ToLower(strings.TrimSpace(answer)) == "yes" {
				saveHostKey(knownHostsFile, hostname, key)
				return nil
			}
			return fmt.Errorf("host key verification failed")
		}

		return err
	}
}

func normalizeRemoteAddr(hostname string, remote net.Addr) net.Addr {
	if remote != nil {
		return remote
	}
	host, port, err := net.SplitHostPort(hostname)
	if err == nil {
		return &net.TCPAddr{IP: net.ParseIP(host), Port: atoiOrZero(port)}
	}
	return fallbackAddr(hostname)
}

func fallbackAddr(hostname string) net.Addr {
	return hostAddr(hostname)
}

type hostAddr string

func (a hostAddr) Network() string { return "tcp" }
func (a hostAddr) String() string  { return string(a) }

func atoiOrZero(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
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

	aliases := knownHostAliases(hostname)

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
				if aliases[h] {
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

func knownHostAliases(hostname string) map[string]bool {
	aliases := map[string]bool{hostname: true}

	host, port, err := net.SplitHostPort(hostname)
	if err == nil {
		aliases[net.JoinHostPort(host, port)] = true
		aliases["["+host+"]:"+port] = true
	}

	if strings.HasPrefix(hostname, "[") {
		host, port, err := net.SplitHostPort(hostname)
		if err == nil {
			aliases[host+":"+port] = true
		}
	}

	return aliases
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
		passphrase, err2 := readPromptPassword()
		fmt.Fprintln(os.Stderr)
		if err2 != nil {
			return nil, err2
		}
		return ssh.ParsePrivateKeyWithPassphrase(data, passphrase)
	}

	return nil, err
}

func keyboardInteractiveChallenge(name, instruction string, questions []string, echos []bool) ([]string, error) {
	return keyboardInteractiveChallengeWithCache(nil, nil)(name, instruction, questions, echos)
}

func keyboardInteractiveChallengeWithCache(cfg *config.ResolvedConfig, cache *PasswordCache) ssh.KeyboardInteractiveChallenge {
	return func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		if cacheableKeyboardPasswordPrompt(questions, echos) {
			if password, ok := cache.Get(cfg); ok {
				return []string{password}, nil
			}
		}

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
				answer, err := readPromptLine()
				if err != nil {
					return nil, err
				}
				answers[i] = answer
			} else {
				pass, err := readPromptPassword()
				fmt.Fprintln(os.Stderr)
				if err != nil {
					return nil, err
				}
				answers[i] = string(pass)
			}
		}
		if cacheableKeyboardPasswordPrompt(questions, echos) {
			cache.Store(cfg, answers[0])
		}
		return answers, nil
	}
}

func cacheableKeyboardPasswordPrompt(questions []string, echos []bool) bool {
	return len(questions) == 1 && len(echos) == 1 && !echos[0]
}
