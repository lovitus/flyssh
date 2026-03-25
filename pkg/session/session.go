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

var globalStdinRouter stdinRouter

// stdinRouter keeps a single reader on os.Stdin for the entire process and
// routes bytes to the currently active interactive SSH session.
type stdinRouter struct {
	mu     sync.RWMutex
	writer io.WriteCloser
	once   sync.Once
}

func (r *stdinRouter) loop() {
	buf := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			r.mu.RLock()
			w := r.writer
			r.mu.RUnlock()
			if w != nil {
				if _, werr := w.Write(buf[:n]); werr != nil {
					r.mu.Lock()
					if r.writer == w {
						r.writer = nil
					}
					r.mu.Unlock()
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (r *stdinRouter) bind(w io.WriteCloser) func() {
	r.once.Do(func() {
		go r.loop()
	})

	r.mu.Lock()
	r.writer = w
	r.mu.Unlock()

	return func() {
		r.mu.Lock()
		if r.writer == w {
			r.writer = nil
		}
		r.mu.Unlock()
	}
}

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
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	stdin, err := session.StdinPipe()
	if err != nil {
		return 1, fmt.Errorf("stdin pipe: %w", err)
	}

	// Enable VT processing on stdout (Windows: ANSI escape support)
	restoreVT := enableVTProcessing()
	defer restoreVT()

	// Put terminal into raw mode for interactive use
	var oldState *term.State
	if !opts.DisableTTY && term.IsTerminal(int(os.Stdin.Fd())) {
		oldState, err = term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil && opts.Verbose {
			log.Printf("Warning: could not set raw terminal: %v", err)
		}
	}

	releaseStdin := globalStdinRouter.bind(stdin)
	defer releaseStdin()

	// Start shell
	if err := session.Shell(); err != nil {
		if oldState != nil {
			term.Restore(int(os.Stdin.Fd()), oldState)
		}
		return 1, fmt.Errorf("start shell: %w", err)
	}

	// Handle window size changes
	stopResize := make(chan struct{})
	defer close(stopResize)
	if !opts.DisableTTY {
		go handleWindowResize(session, stopResize)
	}

	err = session.Wait()

	// Restore terminal
	if oldState != nil {
		term.Restore(int(os.Stdin.Fd()), oldState)
	}

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
		stopResize := make(chan struct{})
		defer close(stopResize)
		go handleWindowResize(session, stopResize)
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
	// Get terminal size — use Stdout on Windows (GetConsoleScreenBufferInfo
	// requires an OUTPUT handle; Stdin is an INPUT handle).
	width, height := 80, 24
	for _, fd := range []int{int(os.Stdout.Fd()), int(os.Stdin.Fd())} {
		if term.IsTerminal(fd) {
			if w, h, err := term.GetSize(fd); err == nil {
				width, height = w, h
				break
			}
		}
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.OPOST:         1, // enable output processing
		ssh.ONLCR:         1, // map NL to CR-NL on output
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	termType := os.Getenv("TERM")
	if termType == "" {
		termType = "xterm-256color"
	}

	return session.RequestPty(termType, height, width, modes)
}

func handleWindowResize(session *ssh.Session, stop <-chan struct{}) {
	// Use Stdout for GetSize (Windows needs OUTPUT handle)
	fd := int(os.Stdout.Fd())
	if !term.IsTerminal(fd) {
		fd = int(os.Stdin.Fd())
		if !term.IsTerminal(fd) {
			return
		}
	}

	// Poll-based window resize detection (cross-platform)
	prevW, prevH, _ := term.GetSize(fd)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			w, h, err := term.GetSize(fd)
			if err != nil {
				continue
			}
			if w != prevW || h != prevH {
				session.WindowChange(h, w)
				prevW, prevH = w, h
			}
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
