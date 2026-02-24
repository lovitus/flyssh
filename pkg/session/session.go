package session

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/flyssh/flyssh/pkg/cli"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// RunInteractiveShell starts an interactive shell session
func RunInteractiveShell(client *ssh.Client, opts *cli.Options) (int, error) {
	session, err := client.NewSession()
	if err != nil {
		return 1, fmt.Errorf("create session: %w", err)
	}
	defer session.Close()

	// Set environment variables
	setEnvVars(session, opts)

	// Request agent forwarding if enabled
	if opts.ForwardAgent {
		if err := requestAgentForwarding(session); err != nil && opts.Verbose {
			log.Printf("Agent forwarding request failed: %v", err)
		}
	}

	// Set up PTY
	if !opts.DisableTTY {
		if err := requestPTY(session, opts); err != nil {
			return 1, fmt.Errorf("request pty: %w", err)
		}
	}

	// Connect stdin/stdout/stderr
	stdin, err := session.StdinPipe()
	if err != nil {
		return 1, fmt.Errorf("stdin pipe: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return 1, fmt.Errorf("stdout pipe: %w", err)
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		return 1, fmt.Errorf("stderr pipe: %w", err)
	}

	// Put terminal into raw mode for interactive use
	var oldState *term.State
	if !opts.DisableTTY && term.IsTerminal(int(os.Stdin.Fd())) {
		oldState, err = term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil && opts.Verbose {
			log.Printf("Warning: could not set raw terminal: %v", err)
		}
	}

	// Start shell
	if err := session.Shell(); err != nil {
		if oldState != nil {
			term.Restore(int(os.Stdin.Fd()), oldState)
		}
		return 1, fmt.Errorf("start shell: %w", err)
	}

	// Handle window size changes
	if !opts.DisableTTY {
		go handleWindowResize(session)
	}

	// Copy I/O
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		io.Copy(stdin, os.Stdin)
		stdin.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(os.Stdout, stdout)
	}()

	go func() {
		defer wg.Done()
		io.Copy(os.Stderr, stderr)
	}()

	err = session.Wait()

	// Restore terminal
	if oldState != nil {
		term.Restore(int(os.Stdin.Fd()), oldState)
	}

	wg.Wait()

	code, sessionErr := exitCodeAndError(err)
	return code, sessionErr
}

// RunCommand executes a single command on the remote host
func RunCommand(client *ssh.Client, opts *cli.Options) (int, error) {
	session, err := client.NewSession()
	if err != nil {
		return 1, fmt.Errorf("create session: %w", err)
	}
	defer session.Close()

	// Set environment variables
	setEnvVars(session, opts)

	// Request agent forwarding if enabled
	if opts.ForwardAgent {
		if err := requestAgentForwarding(session); err != nil && opts.Verbose {
			log.Printf("Agent forwarding request failed: %v", err)
		}
	}

	// Request PTY if -t is specified
	if opts.ForceTTY {
		if err := requestPTY(session, opts); err != nil && opts.Verbose {
			log.Printf("Warning: PTY request failed: %v", err)
		}

		// Put terminal into raw mode
		var oldState *term.State
		if term.IsTerminal(int(os.Stdin.Fd())) {
			oldState, err = term.MakeRaw(int(os.Stdin.Fd()))
			if err != nil && opts.Verbose {
				log.Printf("Warning: could not set raw terminal: %v", err)
			}
			defer func() {
				if oldState != nil {
					term.Restore(int(os.Stdin.Fd()), oldState)
				}
			}()
		}

		// Handle window resize
		go handleWindowResize(session)
	}

	// Connect I/O
	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	// Handle subsystem request
	if opts.Subsystem {
		if err := session.RequestSubsystem(opts.Command); err != nil {
			return 1, fmt.Errorf("subsystem %s: %w", opts.Command, err)
		}
		session.Wait()
		return 0, nil
	}

	err = session.Run(opts.Command)
	code, sessionErr := exitCodeAndError(err)
	return code, sessionErr
}

func requestPTY(session *ssh.Session, opts *cli.Options) error {
	// Get terminal size
	width, height := 80, 24
	if term.IsTerminal(int(os.Stdin.Fd())) {
		w, h, err := term.GetSize(int(os.Stdin.Fd()))
		if err == nil {
			width, height = w, h
		}
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	termType := os.Getenv("TERM")
	if termType == "" {
		termType = "xterm-256color"
	}

	return session.RequestPty(termType, height, width, modes)
}

func handleWindowResize(session *ssh.Session) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return
	}

	// Poll-based window resize detection (cross-platform)
	prevW, prevH, _ := term.GetSize(int(os.Stdin.Fd()))
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		w, h, err := term.GetSize(int(os.Stdin.Fd()))
		if err != nil {
			continue
		}
		if w != prevW || h != prevH {
			session.WindowChange(h, w)
			prevW, prevH = w, h
		}
	}
}

func requestAgentForwarding(session *ssh.Session) error {
	// Request agent forwarding via SSH protocol
	ok, err := session.SendRequest("auth-agent-req@openssh.com", true, nil)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("agent forwarding request denied")
	}
	return nil
}

func setEnvVars(session *ssh.Session, opts *cli.Options) {
	// Set TERM
	if termType := os.Getenv("TERM"); termType != "" {
		session.Setenv("TERM", termType)
	}

	// Set SendEnv variables
	for _, envPattern := range opts.SendEnv {
		if val := os.Getenv(envPattern); val != "" {
			session.Setenv(envPattern, val)
		}
	}
}

// exitCodeAndError returns (exitCode, nil) for clean exits (including
// ssh.ExitError from the remote command), or (1, err) for connection
// errors so the caller can trigger reconnect.
func exitCodeAndError(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	if exitErr, ok := err.(*ssh.ExitError); ok {
		return exitErr.ExitStatus(), nil
	}
	// Connection lost, EOF, etc — propagate so reconnect loop can retry
	return 1, err
}

// KeepAlive sends periodic keep-alive requests
func KeepAlive(client *ssh.Client, interval time.Duration, maxCount int) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	missed := 0
	for range ticker.C {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		if err != nil {
			missed++
			if missed >= maxCount {
				log.Printf("Keep-alive: %d missed responses, closing connection", missed)
				client.Close()
				return
			}
		} else {
			missed = 0
		}
	}
}
