package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/flyssh/flyssh/pkg/auth"
	"github.com/flyssh/flyssh/pkg/cli"
	"github.com/flyssh/flyssh/pkg/config"
	"github.com/flyssh/flyssh/pkg/forwarding"
	"github.com/flyssh/flyssh/pkg/session"
	"github.com/flyssh/flyssh/pkg/socks"
	"golang.org/x/crypto/ssh"
)

// scrubArgs overwrites sensitive values in os.Args so they won't appear in
// /proc/self/cmdline on Linux or Get-Process output on Windows.
// NOTE: This only scrubs Go's copy of argv. Shell history is recorded BEFORE
// the process starts and cannot be controlled by the program.
func scrubArgs() {
	sensitive := map[string]bool{
		"--password": true, "--passwords": true, "--socks-pass": true,
		"--secondhost": true, "--secondhostpass": true,
	}
	for i := 0; i < len(os.Args); i++ {
		arg := os.Args[i]
		// --flag value form
		if sensitive[arg] && i+1 < len(os.Args) {
			os.Args[i+1] = "******"
			i++
			continue
		}
		// --flag=value form
		for prefix := range sensitive {
			if strings.HasPrefix(arg, prefix+"=") {
				os.Args[i] = prefix + "=******"
			}
		}
	}
}

// shouldAutoReconnect returns true if credentials are non-interactive
func shouldAutoReconnect(opts *cli.Options) bool {
	if opts.NoReconnect {
		return false
	}
	if opts.Password != "" || opts.PasswordsCSV != "" {
		return true
	}
	if len(opts.IdentityFiles) > 0 || opts.KeysCSV != "" {
		return true
	}
	if opts.SecondHostKey != "" {
		return true
	}
	return false
}

// buildHopChain constructs the full multi-hop chain from CLI options.
func buildHopChain(opts *cli.Options) []cli.HopSpec {
	var hops []cli.HopSpec

	// Extra hops from positional args
	for _, raw := range opts.ExtraHosts {
		hop, err := cli.ParseHopSpec(raw)
		if err != nil {
			log.Fatalf("bad hop spec %q: %v", raw, err)
		}
		hops = append(hops, hop)
	}

	// Backward compat: --secondhost (only if no extra positional hops)
	if opts.SecondHost != "" && len(hops) == 0 {
		hops = append(hops, cli.HopSpec{
			User:     opts.SecondHostUser,
			Password: opts.SecondHostPassword,
			Host:     opts.SecondHostHostname,
			Port:     opts.SecondHostPort,
			KeyFile:  opts.SecondHostKey,
		})
	}

	// Apply --passwords per hop (index 0 = first extra hop = hop index 1 in chain)
	if opts.PasswordsCSV != "" {
		passwords := strings.Split(opts.PasswordsCSV, ",")
		// Index 0 = first host password, 1+ = extra hops
		if len(passwords) > 0 && passwords[0] != "" && opts.Password == "" {
			opts.Password = passwords[0]
		}
		for i := 1; i < len(passwords); i++ {
			if i-1 < len(hops) && passwords[i] != "" {
				hops[i-1].Password = passwords[i]
			}
		}
	}

	// Apply --keys per hop
	if opts.KeysCSV != "" {
		keys := strings.Split(opts.KeysCSV, ",")
		// Index 0 = first host key
		if len(keys) > 0 && keys[0] != "" {
			opts.IdentityFiles = append([]string{keys[0]}, opts.IdentityFiles...)
		}
		for i := 1; i < len(keys); i++ {
			if i-1 < len(hops) && keys[i] != "" {
				hops[i-1].KeyFile = keys[i]
			}
		}
	} else if len(opts.IdentityFiles) > 0 {
		// --key applies to all hops that don't have a specific key
		for i := range hops {
			if hops[i].KeyFile == "" {
				hops[i].KeyFile = opts.IdentityFiles[0]
			}
		}
	}

	return hops
}

func main() {
	// Parse args first, then immediately scrub sensitive values from argv
	opts, err := cli.ParseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "flyssh: %v\n", err)
		os.Exit(255)
	}
	scrubArgs()

	if opts.ShowVersion {
		fmt.Println("flyssh version 1.0.0 (Go SSH client with SOCKS5 proxy support)")
		os.Exit(0)
	}

	if opts.Host == "" {
		cli.PrintUsage()
		os.Exit(255)
	}

	reconnectDelay := time.Duration(opts.ReconnectDelay) * time.Second
	if reconnectDelay <= 0 {
		reconnectDelay = 3 * time.Second
	}
	autoReconnect := shouldAutoReconnect(opts)

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		os.Exit(0)
	}()

	firstAttempt := true
	for {
		exitCode, sessionErr := runOnce(opts)

		if sessionErr == nil {
			// Clean exit (user typed exit, command finished normally)
			os.Exit(exitCode)
		}

		if !autoReconnect {
			if firstAttempt {
				fmt.Fprintf(os.Stderr, "flyssh: %v\n", sessionErr)
			}
			os.Exit(exitCode)
		}

		firstAttempt = false
		fmt.Fprintf(os.Stderr, "\nflyssh: connection lost: %v\n", sessionErr)
		fmt.Fprintf(os.Stderr, "flyssh: reconnecting in %v...\n", reconnectDelay)
		time.Sleep(reconnectDelay)
	}
}

// runOnce performs a single connect-session cycle.
// Returns (exitCode, nil) for clean exit, (exitCode, err) for connection loss / error.
func runOnce(opts *cli.Options) (int, error) {
	// Load SSH config for first host
	sshConfig := config.LoadSSHConfig(opts)
	if opts.Verbose {
		log.Printf("[host1] Resolved: user=%s host=%s port=%d", sshConfig.User, sshConfig.Hostname, sshConfig.Port)
	}

	// Connect first host
	firstClient, err := connectFirstHost(sshConfig, opts)
	if err != nil {
		return 255, fmt.Errorf("host1: %w", err)
	}
	defer func() { forwarding.CleanupClient(firstClient); firstClient.Close() }()

	if opts.Verbose {
		log.Printf("[host1] Connected to %s:%d", sshConfig.Hostname, sshConfig.Port)
	}

	// Build and connect multi-hop chain
	hops := buildHopChain(opts)
	allClients := []*ssh.Client{firstClient}
	finalClient := firstClient

	for i, hop := range hops {
		nextClient, hopErr := connectHop(finalClient, hop, opts, i+2)
		if hopErr != nil {
			return 255, fmt.Errorf("hop%d: %w", i+2, hopErr)
		}
		defer func(c *ssh.Client) { forwarding.CleanupClient(c); c.Close() }(nextClient)
		allClients = append(allClients, nextClient)
		finalClient = nextClient
	}

	// Start keepalive on all clients in the chain
	stopKeepalive := make(chan struct{})
	if sshConfig.ServerAliveInterval > 0 {
		interval := time.Duration(sshConfig.ServerAliveInterval) * time.Second
		for _, c := range allClients {
			go keepAliveUntil(c, interval, sshConfig.ServerAliveCountMax, stopKeepalive)
		}
	}
	defer close(stopKeepalive)

	// Start port forwarding (all on finalClient)
	for _, lf := range opts.LocalForwards {
		go func(spec string) {
			if err := forwarding.StartLocalForward(finalClient, spec, opts.Verbose); err != nil {
				log.Printf("Local forward error (%s): %v", spec, err)
			}
		}(lf)
	}
	for _, rf := range opts.RemoteForwards {
		go func(spec string) {
			if err := forwarding.StartRemoteForward(finalClient, spec, opts.Verbose); err != nil {
				log.Printf("Remote forward error (%s): %v", spec, err)
			}
		}(rf)
	}
	for _, dp := range opts.DynamicForwards {
		go func(spec string) {
			if err := forwarding.StartDynamicForward(finalClient, spec, opts.Verbose); err != nil {
				log.Printf("Dynamic forward error (%s): %v", spec, err)
			}
		}(dp)
	}

	// Stdio forwarding (-W)
	if opts.StdioForward != "" {
		conn, err := finalClient.Dial("tcp", opts.StdioForward)
		if err != nil {
			return 255, fmt.Errorf("stdio forward to %s: %w", opts.StdioForward, err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); io.Copy(conn, os.Stdin) }()
		go func() { defer wg.Done(); io.Copy(os.Stdout, conn) }()
		wg.Wait()
		return 0, nil
	}

	// Forwarding-only mode (-N): wait for connection to die
	if opts.NoCommand {
		if opts.Verbose {
			log.Printf("No command mode (-N), forwarding only")
		}
		err := firstClient.Wait()
		if err != nil {
			return 255, fmt.Errorf("connection closed: %w", err)
		}
		return 0, nil
	}

	// Run interactive shell or command
	var exitCode int
	if opts.Command != "" {
		exitCode, err = session.RunCommand(finalClient, opts)
	} else {
		exitCode, err = session.RunInteractiveShell(finalClient, opts)
	}
	if err != nil {
		return exitCode, err
	}
	return exitCode, nil
}

// keepAliveUntil sends keepalives until stop channel is closed
func keepAliveUntil(client *ssh.Client, interval time.Duration, maxCount int, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	misses := 0
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				misses++
				if maxCount > 0 && misses >= maxCount {
					client.Close()
					return
				}
			} else {
				misses = 0
			}
		}
	}
}

// connectFirstHost establishes the SSH connection to the first host
func connectFirstHost(sshConfig *config.ResolvedConfig, opts *cli.Options) (*ssh.Client, error) {
	authMethods, err := auth.BuildAuthMethods(sshConfig, opts)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	clientConfig := &ssh.ClientConfig{
		User:            sshConfig.User,
		Auth:            authMethods,
		HostKeyCallback: auth.GetHostKeyCallback(sshConfig, opts),
		Timeout:         sshConfig.ConnectTimeout,
	}

	addr := net.JoinHostPort(sshConfig.Hostname, strconv.Itoa(sshConfig.Port))

	if sshConfig.ProxyJump != "" && sshConfig.SocksProxy == "" {
		return connectViaJumpHost(sshConfig, clientConfig, opts)
	}

	var conn net.Conn
	if sshConfig.SocksProxy != "" {
		if opts.Verbose {
			log.Printf("[host1] Connecting to %s via SOCKS5 %s", addr, sshConfig.SocksProxy)
		}
		conn, err = socks.DialViaSocks5(sshConfig.SocksProxy, addr, sshConfig.SocksUser, sshConfig.SocksPassword)
	} else {
		if opts.Verbose {
			log.Printf("[host1] Connecting to %s directly", addr)
		}
		conn, err = net.DialTimeout("tcp", addr, sshConfig.ConnectTimeout)
	}
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, clientConfig)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", addr, err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// connectHop connects to a hop through the previous SSH client.
// hopNum is for logging (2 = second host, 3 = third, etc.)
func connectHop(prevClient *ssh.Client, hop cli.HopSpec, opts *cli.Options, hopNum int) (*ssh.Client, error) {
	addr := net.JoinHostPort(hop.Host, strconv.Itoa(hop.Port))

	var identityFiles []string
	if hop.KeyFile != "" {
		identityFiles = []string{hop.KeyFile}
	}

	hopCfg := &config.ResolvedConfig{
		User:           hop.User,
		Hostname:       hop.Host,
		Port:           hop.Port,
		IdentityFiles:  identityFiles,
		ConnectTimeout: 30 * time.Second,
	}

	hopAuthMethods, err := auth.BuildAuthMethodsForHop(hopCfg, opts, hop.Password)
	if err != nil {
		return nil, fmt.Errorf("hop%d auth: %w", hopNum, err)
	}

	hopClientConfig := &ssh.ClientConfig{
		User:            hop.User,
		Auth:            hopAuthMethods,
		HostKeyCallback: auth.GetHostKeyCallback(hopCfg, opts),
		Timeout:         30 * time.Second,
	}

	if opts.Verbose {
		log.Printf("[hop%d] Dialing %s@%s through hop%d", hopNum, hop.User, addr, hopNum-1)
	}

	conn, err := forwarding.DialTCP(prevClient, addr, opts.Verbose)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, hopClientConfig)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", addr, err)
	}

	client := ssh.NewClient(sshConn, chans, reqs)
	if opts.Verbose {
		log.Printf("[hop%d] Connected to %s@%s:%d", hopNum, hop.User, hop.Host, hop.Port)
	}
	return client, nil
}

func connectViaJumpHost(sshConfig *config.ResolvedConfig, targetConfig *ssh.ClientConfig, opts *cli.Options) (*ssh.Client, error) {
	jumps := strings.Split(sshConfig.ProxyJump, ",")

	var currentClient *ssh.Client
	for i, jump := range jumps {
		jump = strings.TrimSpace(jump)
		jumpHost, jumpPort, jumpUser := parseJumpSpec(jump, sshConfig.User)

		jumpAuthMethods, err := auth.BuildAuthMethods(&config.ResolvedConfig{
			User:           jumpUser,
			Hostname:       jumpHost,
			Port:           jumpPort,
			IdentityFiles:  sshConfig.IdentityFiles,
			ConnectTimeout: sshConfig.ConnectTimeout,
		}, opts)
		if err != nil {
			return nil, fmt.Errorf("jump host %s auth: %w", jump, err)
		}

		jumpConfig := &ssh.ClientConfig{
			User:            jumpUser,
			Auth:            jumpAuthMethods,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         sshConfig.ConnectTimeout,
		}

		jumpAddr := net.JoinHostPort(jumpHost, strconv.Itoa(jumpPort))

		if i == 0 {
			// First jump - connect directly (or via SOCKS5 if set)
			var conn net.Conn
			if sshConfig.SocksProxy != "" {
				conn, err = socks.DialViaSocks5(sshConfig.SocksProxy, jumpAddr, sshConfig.SocksUser, sshConfig.SocksPassword)
			} else {
				conn, err = net.DialTimeout("tcp", jumpAddr, sshConfig.ConnectTimeout)
			}
			if err != nil {
				return nil, fmt.Errorf("connect to jump host %s: %w", jump, err)
			}
			sshConn, chans, reqs, err := ssh.NewClientConn(conn, jumpAddr, jumpConfig)
			if err != nil {
				return nil, fmt.Errorf("ssh to jump host %s: %w", jump, err)
			}
			currentClient = ssh.NewClient(sshConn, chans, reqs)
		} else {
			// Subsequent jumps - tunnel through previous client
			conn, err := currentClient.Dial("tcp", jumpAddr)
			if err != nil {
				return nil, fmt.Errorf("dial through jump %s: %w", jump, err)
			}
			sshConn, chans, reqs, err := ssh.NewClientConn(conn, jumpAddr, jumpConfig)
			if err != nil {
				return nil, fmt.Errorf("ssh through jump %s: %w", jump, err)
			}
			currentClient = ssh.NewClient(sshConn, chans, reqs)
		}

		if opts.Verbose {
			log.Printf("Connected to jump host %s (%d/%d)", jump, i+1, len(jumps))
		}
	}

	// Final hop to target
	targetAddr := net.JoinHostPort(sshConfig.Hostname, strconv.Itoa(sshConfig.Port))
	conn, err := currentClient.Dial("tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("dial target through jump chain: %w", err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, targetAddr, targetConfig)
	if err != nil {
		return nil, fmt.Errorf("ssh to target through jump chain: %w", err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

func parseJumpSpec(spec, defaultUser string) (host string, port int, user string) {
	user = defaultUser
	port = 22
	host = spec

	if idx := strings.LastIndex(spec, "@"); idx != -1 {
		user = spec[:idx]
		host = spec[idx+1:]
	}

	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if pn, err := strconv.Atoi(p); err == nil {
			port = pn
		}
	}
	return
}
