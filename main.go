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
		"--password": true, "--socks-pass": true, "--secondhost": true,
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

	// Load SSH config for first host
	sshConfig := config.LoadSSHConfig(opts)
	if opts.Verbose {
		log.Printf("[host1] Resolved: user=%s host=%s port=%d", sshConfig.User, sshConfig.Hostname, sshConfig.Port)
		if sshConfig.SocksProxy != "" {
			log.Printf("[host1] SOCKS5 proxy: %s", sshConfig.SocksProxy)
		}
	}

	// Build auth methods for first host
	authMethods, err := auth.BuildAuthMethods(sshConfig, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flyssh: auth error: %v\n", err)
		os.Exit(255)
	}

	clientConfig := &ssh.ClientConfig{
		User:            sshConfig.User,
		Auth:            authMethods,
		HostKeyCallback: auth.GetHostKeyCallback(sshConfig, opts),
		Timeout:         sshConfig.ConnectTimeout,
	}

	addr := net.JoinHostPort(sshConfig.Hostname, strconv.Itoa(sshConfig.Port))

	// Connect to first host (direct, via SOCKS5, or via ProxyJump)
	var firstClient *ssh.Client
	if sshConfig.ProxyJump != "" && sshConfig.SocksProxy == "" {
		firstClient, err = connectViaJumpHost(sshConfig, clientConfig, opts)
	} else {
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
			fmt.Fprintf(os.Stderr, "flyssh: connect error: %v\n", err)
			os.Exit(255)
		}
		sshConn, chans, reqs, err2 := ssh.NewClientConn(conn, addr, clientConfig)
		if err2 != nil {
			fmt.Fprintf(os.Stderr, "flyssh: ssh handshake error: %v\n", err2)
			os.Exit(255)
		}
		firstClient = ssh.NewClient(sshConn, chans, reqs)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "flyssh: %v\n", err)
		os.Exit(255)
	}
	defer firstClient.Close()

	if opts.Verbose {
		log.Printf("[host1] Connected to %s", addr)
	}

	// Determine the "final" client for shell/command and port forwarding
	// If --secondhost is set, connect through firstClient to secondHost
	finalClient := firstClient

	if opts.SecondHost != "" {
		finalClient, err = connectSecondHost(firstClient, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "flyssh: second host error: %v\n", err)
			os.Exit(255)
		}
		defer finalClient.Close()
		if opts.Verbose {
			log.Printf("[host2] Connected to %s@%s:%d",
				opts.SecondHostUser, opts.SecondHostHostname, opts.SecondHostPort)
		}
	}

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		finalClient.Close()
		firstClient.Close()
		os.Exit(0)
	}()

	// Port forwarding applies to finalClient (second host if present, else first)
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

	// Start keepalive if configured
	if sshConfig.ServerAliveInterval > 0 {
		go session.KeepAlive(firstClient, time.Duration(sshConfig.ServerAliveInterval)*time.Second, sshConfig.ServerAliveCountMax)
		if opts.SecondHost != "" {
			go session.KeepAlive(finalClient, time.Duration(sshConfig.ServerAliveInterval)*time.Second, sshConfig.ServerAliveCountMax)
		}
	}

	// Stdio forwarding (-W host:port) — on finalClient
	if opts.StdioForward != "" {
		conn, err := finalClient.Dial("tcp", opts.StdioForward)
		if err != nil {
			fmt.Fprintf(os.Stderr, "flyssh: stdio forward to %s: %v\n", opts.StdioForward, err)
			os.Exit(255)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); io.Copy(conn, os.Stdin) }()
		go func() { defer wg.Done(); io.Copy(os.Stdout, conn) }()
		wg.Wait()
		os.Exit(0)
	}

	// If -N, just wait (forwarding only)
	if opts.NoCommand {
		if opts.Verbose {
			log.Printf("No command mode (-N), forwarding only")
		}
		select {}
	}

	// Run command or interactive shell — on finalClient
	exitCode := 0
	if opts.Command != "" {
		exitCode, err = session.RunCommand(finalClient, opts)
	} else {
		exitCode, err = session.RunInteractiveShell(finalClient, opts)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "flyssh: %v\n", err)
		if exitCode == 0 {
			exitCode = 1
		}
	}
	os.Exit(exitCode)
}

// connectSecondHost connects to the second host through the first SSH client
func connectSecondHost(firstClient *ssh.Client, opts *cli.Options) (*ssh.Client, error) {
	secondAddr := net.JoinHostPort(opts.SecondHostHostname, strconv.Itoa(opts.SecondHostPort))

	// Build identity files for second host
	var identityFiles []string
	if opts.SecondHostKey != "" {
		identityFiles = []string{opts.SecondHostKey}
	}

	secondCfg := &config.ResolvedConfig{
		User:           opts.SecondHostUser,
		Hostname:       opts.SecondHostHostname,
		Port:           opts.SecondHostPort,
		IdentityFiles:  identityFiles,
		ConnectTimeout: 30 * time.Second,
	}

	secondAuthMethods, err := auth.BuildAuthMethodsForSecondHost(secondCfg, opts)
	if err != nil {
		return nil, fmt.Errorf("second host auth: %w", err)
	}

	secondClientConfig := &ssh.ClientConfig{
		User:            opts.SecondHostUser,
		Auth:            secondAuthMethods,
		HostKeyCallback: auth.GetHostKeyCallback(secondCfg, opts),
		Timeout:         30 * time.Second,
	}

	if opts.Verbose {
		log.Printf("[host2] Dialing %s through host1", secondAddr)
	}

	conn, err := firstClient.Dial("tcp", secondAddr)
	if err != nil {
		return nil, fmt.Errorf("dial %s through host1: %w", secondAddr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, secondAddr, secondClientConfig)
	if err != nil {
		return nil, fmt.Errorf("ssh handshake with %s: %w", secondAddr, err)
	}

	return ssh.NewClient(sshConn, chans, reqs), nil
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
