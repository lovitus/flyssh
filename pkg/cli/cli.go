package cli

import (
	"fmt"
	"os"
	"strings"
)

// Options holds all parsed CLI arguments
type Options struct {
	Host           string
	Port           int
	User           string
	IdentityFiles  []string
	Command        string
	Verbose        bool
	Quiet          bool
	NoCommand      bool   // -N
	ForceTTY       bool   // -t
	DisableTTY     bool   // -T
	Compression    bool   // -C
	ForwardAgent   bool   // -A
	NoForwardAgent bool   // -a
	IPv4Only       bool   // -4
	IPv6Only       bool   // -6
	ShowVersion    bool   // -V
	Gateway        bool   // -g (allow remote hosts to connect to local forwarded ports)
	ExitOnForward  bool   // -f (go to background - we just detach stdin)
	StrictHostKey  string // strict|ask|no
	ConfigFile     string // -F
	LoginName      string // -l
	CipherSpec     string // -c
	MACSpec        string // -m
	LogFile        string // -E
	BindAddress    string // -b
	EscapeChar     string // -e
	ProxyJump      string // -J

	// SOCKS5 proxy (our addition)
	SocksProxy    string // --socks host:port
	SocksUser     string // --socks-user
	SocksPassword string // --socks-pass

	// Password auth
	Password     string // --password (direct password for first host)
	PasswordEnv  string // --password-env VAR (read password from env var)
	PasswordFile string // --password-file PATH (read password from file)

	// Second host (two-hop jump)
	SecondHost    string // --secondhost user:pass@host:port (raw spec)
	SecondHostKey string // --secondhostkey /path/to/key

	// Parsed second host fields (filled after parsing)
	SecondHostUser     string
	SecondHostPassword string
	SecondHostHostname string
	SecondHostPort     int

	// Port forwarding
	LocalForwards   []string // -L
	RemoteForwards  []string // -R
	DynamicForwards []string // -D

	// -o key=value options
	SSHOptions map[string]string

	// -W for stdio forwarding
	StdioForward string

	// Extra env to send
	SendEnv []string

	// X11 forwarding
	ForwardX11        bool // -X
	ForwardX11Trusted bool // -Y

	// Subsystem
	Subsystem bool // -s
}

func PrintUsage() {
	fmt.Fprintf(os.Stderr, `usage: flyssh [options] [user@]hostname [command [argument ...]]

Options:
  -4              Force IPv4
  -6              Force IPv6
  -A              Enable agent forwarding
  -a              Disable agent forwarding
  -b bind_addr    Bind address for outgoing connection
  -C              Enable compression
  -c cipher       Cipher specification
  -D [bind:]port  Dynamic port forwarding (SOCKS5)
  -E log_file     Log to file instead of stderr
  -e char         Escape character (default: ~)
  -F config       Config file
  -f              Go to background after auth
  -g              Allow remote hosts to connect to forwarded ports
  -i identity     Identity file (private key)
  -J destination  ProxyJump
  -L [bind:]port:host:port  Local port forwarding
  -l login_name   Login name
  -m mac_spec     MAC specification
  -N              No remote command (forwarding only)
  -o option       SSH option in key=value format
  -p port         Port (default: 22)
  -q              Quiet mode
  -R [bind:]port:host:port  Remote port forwarding
  -s              Subsystem request
  -T              Disable pseudo-terminal
  -t              Force pseudo-terminal allocation
  -V              Show version
  -v              Verbose mode
  -W host:port    Stdio forwarding
  -X              Enable X11 forwarding
  -Y              Enable trusted X11 forwarding

SOCKS5 Proxy (flyssh extension):
  --socks host:port     SOCKS5 proxy server
  --socks-user user     SOCKS5 username
  --socks-pass pass     SOCKS5 password

Authentication:
  --password pass       Password for first host (see security notes below)
  --password-env VAR    Read password from environment variable
  --password-file PATH  Read password from file (more secure)

Two-hop Jump:
  --secondhost user:pass@host:port  Second host connection string
  --secondhostkey PATH              Identity file for second host

  Port forwarding (-D/-L/-R) applies to second host when present.

Security Note:
  --password on the command line may be visible in shell history and
  process listings. Use --password-env or --password-file for better
  security. The program will attempt to scrub argv at startup, but
  shell history cannot be controlled by the program.
`)
}

func ParseArgs(args []string) (*Options, error) {
	opts := &Options{
		Port:          0, // 0 = not set, will use config or default 22
		EscapeChar:    "~",
		StrictHostKey: "",
		SSHOptions:    make(map[string]string),
	}

	i := 0
	for i < len(args) {
		arg := args[i]

		// Long options (our extension)
		if strings.HasPrefix(arg, "--") {
			switch {
			case arg == "--socks" && i+1 < len(args):
				i++
				opts.SocksProxy = args[i]
			case strings.HasPrefix(arg, "--socks="):
				opts.SocksProxy = arg[len("--socks="):]
			case arg == "--socks-user" && i+1 < len(args):
				i++
				opts.SocksUser = args[i]
			case strings.HasPrefix(arg, "--socks-user="):
				opts.SocksUser = arg[len("--socks-user="):]
			case arg == "--socks-pass" && i+1 < len(args):
				i++
				opts.SocksPassword = args[i]
			case strings.HasPrefix(arg, "--socks-pass="):
				opts.SocksPassword = arg[len("--socks-pass="):]
			case arg == "--password" && i+1 < len(args):
				i++
				opts.Password = args[i]
			case strings.HasPrefix(arg, "--password="):
				opts.Password = arg[len("--password="):]
			case arg == "--password-env" && i+1 < len(args):
				i++
				opts.PasswordEnv = args[i]
			case strings.HasPrefix(arg, "--password-env="):
				opts.PasswordEnv = arg[len("--password-env="):]
			case arg == "--password-file" && i+1 < len(args):
				i++
				opts.PasswordFile = args[i]
			case strings.HasPrefix(arg, "--password-file="):
				opts.PasswordFile = arg[len("--password-file="):]
			case arg == "--secondhost" && i+1 < len(args):
				i++
				opts.SecondHost = args[i]
			case strings.HasPrefix(arg, "--secondhost="):
				opts.SecondHost = arg[len("--secondhost="):]
			case arg == "--secondhostkey" && i+1 < len(args):
				i++
				opts.SecondHostKey = args[i]
			case strings.HasPrefix(arg, "--secondhostkey="):
				opts.SecondHostKey = arg[len("--secondhostkey="):]
			case arg == "--version":
				opts.ShowVersion = true
			case arg == "--help":
				PrintUsage()
				os.Exit(0)
			default:
				return nil, fmt.Errorf("unknown option: %s", arg)
			}
			i++
			continue
		}

		if arg[0] != '-' {
			// First non-option is [user@]host
			if opts.Host == "" {
				opts.Host = arg
			} else {
				// Remaining args are the command
				opts.Command = strings.Join(args[i:], " ")
				break
			}
			i++
			continue
		}

		// Single-char flags that can be combined (no arg): 4, 6, A, a, C, f, g, N, q, s, T, t, v, V, X, Y
		// Flags that require an argument: b, c, D, E, e, F, i, J, L, l, m, o, p, R, W

		flagStr := arg[1:]
		j := 0
		for j < len(flagStr) {
			ch := flagStr[j]
			switch ch {
			case '4':
				opts.IPv4Only = true
				j++
			case '6':
				opts.IPv6Only = true
				j++
			case 'A':
				opts.ForwardAgent = true
				j++
			case 'a':
				opts.NoForwardAgent = true
				j++
			case 'C':
				opts.Compression = true
				j++
			case 'f':
				opts.ExitOnForward = true
				j++
			case 'g':
				opts.Gateway = true
				j++
			case 'N':
				opts.NoCommand = true
				j++
			case 'q':
				opts.Quiet = true
				j++
			case 's':
				opts.Subsystem = true
				j++
			case 'T':
				opts.DisableTTY = true
				j++
			case 't':
				opts.ForceTTY = true
				j++
			case 'v':
				opts.Verbose = true
				j++
			case 'V':
				opts.ShowVersion = true
				j++
			case 'X':
				opts.ForwardX11 = true
				j++
			case 'Y':
				opts.ForwardX11Trusted = true
				j++

			// Flags requiring arguments
			case 'b', 'c', 'D', 'E', 'e', 'F', 'i', 'J', 'L', 'l', 'm', 'o', 'p', 'R', 'W':
				var val string
				rest := flagStr[j+1:]
				if rest != "" {
					val = rest
				} else {
					i++
					if i >= len(args) {
						return nil, fmt.Errorf("option -%c requires an argument", ch)
					}
					val = args[i]
				}

				switch ch {
				case 'b':
					opts.BindAddress = val
				case 'c':
					opts.CipherSpec = val
				case 'D':
					opts.DynamicForwards = append(opts.DynamicForwards, val)
				case 'E':
					opts.LogFile = val
				case 'e':
					opts.EscapeChar = val
				case 'F':
					opts.ConfigFile = val
				case 'i':
					opts.IdentityFiles = append(opts.IdentityFiles, val)
				case 'J':
					opts.ProxyJump = val
				case 'L':
					opts.LocalForwards = append(opts.LocalForwards, val)
				case 'l':
					opts.LoginName = val
				case 'm':
					opts.MACSpec = val
				case 'o':
					parts := strings.SplitN(val, "=", 2)
					if len(parts) == 2 {
						opts.SSHOptions[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
					} else {
						// Support "key value" format too
						parts = strings.SplitN(val, " ", 2)
						if len(parts) == 2 {
							opts.SSHOptions[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
						}
					}
				case 'p':
					p := 0
					for _, c := range val {
						if c >= '0' && c <= '9' {
							p = p*10 + int(c-'0')
						}
					}
					if p > 0 && p < 65536 {
						opts.Port = p
					}
				case 'R':
					opts.RemoteForwards = append(opts.RemoteForwards, val)
				case 'W':
					opts.StdioForward = val
				}

				// Consumed the rest of this arg
				j = len(flagStr)

			default:
				return nil, fmt.Errorf("unknown option: -%c", ch)
			}
		}
		i++
	}

	// Parse user@host
	if opts.Host != "" && strings.Contains(opts.Host, "@") {
		parts := strings.SplitN(opts.Host, "@", 2)
		opts.User = parts[0]
		opts.Host = parts[1]
	}

	// -l overrides user@host
	if opts.LoginName != "" {
		opts.User = opts.LoginName
	}

	// Resolve password from env or file
	if opts.PasswordEnv != "" && opts.Password == "" {
		opts.Password = os.Getenv(opts.PasswordEnv)
	}
	if opts.PasswordFile != "" && opts.Password == "" {
		data, err := os.ReadFile(opts.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("read password file: %w", err)
		}
		opts.Password = strings.TrimRight(string(data), "\r\n")
	}

	// Parse --secondhost user:pass@host:port
	if opts.SecondHost != "" {
		if err := parseSecondHost(opts); err != nil {
			return nil, fmt.Errorf("--secondhost: %w", err)
		}
	}

	return opts, nil
}

// parseSecondHost parses "user:pass@host:port" into SecondHost* fields
func parseSecondHost(opts *Options) error {
	spec := opts.SecondHost

	// Split on last '@' to separate user:pass from host:port
	atIdx := strings.LastIndex(spec, "@")
	if atIdx == -1 {
		return fmt.Errorf("expected user:pass@host:port or user@host:port, got %q", spec)
	}

	userPart := spec[:atIdx]
	hostPart := spec[atIdx+1:]

	// Parse user:password (password is optional)
	if colonIdx := strings.Index(userPart, ":"); colonIdx != -1 {
		opts.SecondHostUser = userPart[:colonIdx]
		opts.SecondHostPassword = userPart[colonIdx+1:]
	} else {
		opts.SecondHostUser = userPart
	}

	// Parse host:port
	opts.SecondHostPort = 22
	if h, p, err := splitHostPort(hostPart); err == nil {
		opts.SecondHostHostname = h
		opts.SecondHostPort = p
	} else {
		opts.SecondHostHostname = hostPart
	}

	if opts.SecondHostHostname == "" {
		return fmt.Errorf("empty hostname in %q", spec)
	}
	if opts.SecondHostUser == "" {
		return fmt.Errorf("empty user in %q", spec)
	}

	return nil
}

func splitHostPort(s string) (string, int, error) {
	// Handle IPv6 [::1]:port
	if strings.HasPrefix(s, "[") {
		if idx := strings.LastIndex(s, "]:"); idx != -1 {
			host := s[1:idx]
			p := 0
			for _, c := range s[idx+2:] {
				if c >= '0' && c <= '9' {
					p = p*10 + int(c-'0')
				}
			}
			if p > 0 && p < 65536 {
				return host, p, nil
			}
		}
	}

	// host:port
	if idx := strings.LastIndex(s, ":"); idx != -1 {
		host := s[:idx]
		p := 0
		for _, c := range s[idx+1:] {
			if c >= '0' && c <= '9' {
				p = p*10 + int(c-'0')
			} else {
				return "", 0, fmt.Errorf("non-numeric port")
			}
		}
		if p > 0 && p < 65536 {
			return host, p, nil
		}
	}

	return "", 0, fmt.Errorf("no port")
}
