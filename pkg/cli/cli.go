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
	SecondHost     string // --secondhost user:pass@host:port (raw spec)
	SecondHostKey  string // --secondhostkey /path/to/key
	SecondHostPass string // --secondhostpass (separate password flag, overrides inline)

	// Parsed second host fields (filled after parsing)
	SecondHostUser     string
	SecondHostPassword string
	SecondHostHostname string
	SecondHostPort     int

	// Auto-reconnect
	NoReconnect    bool // --no-reconnect
	ReconnectDelay int  // --reconnect-delay seconds (default 3)

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

	// Multi-hop: additional hosts beyond the first positional arg
	ExtraHosts []string // raw specs: "user:pass@host:port"

	// Per-hop keys/passwords (comma-separated, empty slots = skip)
	KeysCSV      string // --keys "key1,,key3,,,key6,"
	PasswordsCSV string // --passwords "pass1,,pass3"

	// File transfer modes (mutually exclusive)
	RsyncUpload   string // --rsync-upload '...'
	RsyncDownload string // --rsync-download '...'
	ScpUpload     string // --scp-upload '...'
	ScpDownload   string // --scp-download '...'

	// Local SSH gateway mode
	SSHGateway string // --ssh-gateway 'user:pass@bind:port'

	// Built-in mosh-over-FlySSH mode
	Mosh        bool   // --mosh
	MoshSession string // --mosh-session NAME

	// Windows companion GUI and hidden GUI subprocess commands
	Wingui          bool   // --wingui
	GuiInternalHome bool   // --gui-internal-home
	GuiInternalList string // --gui-internal-list DIR
}

// HopSpec describes a single hop in a multi-hop SSH chain.
type HopSpec struct {
	User     string
	Password string
	Host     string
	Port     int
	KeyFile  string
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
  -c ciphers      Ciphers, comma-separated
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
  -m macs         MACs, comma-separated
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
  --help          Show this help
  --version       Show version

SOCKS5 Proxy (flyssh extension):
  --socks host:port     SOCKS5 proxy server
  --socks-user user     SOCKS5 username
  --socks-pass pass     SOCKS5 password

Authentication:
  --password pass       Password for first host (see security notes below)
  --password-env VAR    Read password from environment variable
  --password-file PATH  Read password from file (more secure)

Multi-hop (chain through unlimited machines):
  flyssh user1:pass1@host1 user2:pass2@host2 user3@host3:2222 [command]
  Each positional arg with @ is a hop. Last hop gets the shell/forwarding.
  Use -- before a remote command if the command contains @ or could look like a hop:
  flyssh user@host -- "printf '%%s\n' 'a@b'"
  --keys "k1,,k3,,,k6,"   Per-hop identity files (comma-separated, empty=skip)
  --passwords "p1,,p3"    Per-hop passwords (comma-separated, empty=skip)
  Use -i FILE for a single identity applied to all hops when --keys is not set.

  Password escaping (inline or --passwords):
    Backslash:  user:p\@ss\:word@host:22
    Quotes:     user:"p@ss:word"@host:22  or  user:'p@ss:word'@host:22

  Port forwarding (-D/-L/-R) applies to the last hop.

Legacy two-hop (still supported):
  --secondhost user:pass@host:port  Second host connection string
  --secondhostkey PATH              Identity file for second host
  --secondhostpass PASS             Password for second host (overrides inline)

Easy Forwarding (GOST-style):
  -dynamicproxy://[host:]port          Dynamic SOCKS5 proxy
  -ltcp://[host:]port/[host:]port[,...]  Local forward  (comma-separated pairs)
  -rtcp://[host:]port/[host:]port[,...]  Remote forward (comma-separated pairs)

  Format: host:port | :port | port — missing host defaults to 127.0.0.1
  Example: -ltcp://:8081/host3:22      listen local :8081 → host3:22 via chain
  Example: -ltcp://:5000/:5000,:2222/192.168.1.1:22  two local forwards in one flag
  Example: -rtcp://0.0.0.0:8082/127.0.0.1:80  remote :8082 → local :80

Reconnect:
  --no-reconnect          Disable auto-reconnect (enabled by default with --password)
  --reconnect-delay N     Seconds between reconnect attempts (default: 3)

File Transfer:
  --rsync-upload '...'    Run rsync upload using flyssh-managed transport
  --rsync-download '...'  Run rsync download using flyssh-managed transport
  --scp-upload '...'      Run built-in SCP upload using current flyssh route
  --scp-download '...'    Run built-in SCP download using current flyssh route
  --wingui                Launch Windows companion transfer GUI

SSH Gateway:
  --ssh-gateway 'user:pass@bind:port'
                          Start local SSH gateway for third-party clients

Mosh:
  --mosh                  Start built-in mosh-over-FlySSH terminal session
  --mosh-session NAME     Reattach/create a fixed mosh session name
                          NAME: [A-Za-z0-9._-], max 64 chars
                          Carries mosh datagrams through current SOCKS/multi-hop route

Security Note:
  --password on the command line may be visible in shell history and
  process listings. Use --password-env or --password-file for better
  security. The program will attempt to scrub argv at startup, but
  shell history cannot be controlled by the program. --ssh-gateway
  includes a local gateway password and has the same shell-history risk.
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

		if arg == "--" {
			if opts.Host == "" {
				return nil, fmt.Errorf("-- command separator requires a host")
			}
			opts.Command = strings.Join(args[i+1:], " ")
			break
		}

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
			case arg == "--secondhostpass" && i+1 < len(args):
				i++
				opts.SecondHostPass = args[i]
			case strings.HasPrefix(arg, "--secondhostpass="):
				opts.SecondHostPass = arg[len("--secondhostpass="):]
			case arg == "--keys" && i+1 < len(args):
				i++
				opts.KeysCSV = args[i]
			case strings.HasPrefix(arg, "--keys="):
				opts.KeysCSV = arg[len("--keys="):]
			case arg == "--passwords" && i+1 < len(args):
				i++
				opts.PasswordsCSV = args[i]
			case strings.HasPrefix(arg, "--passwords="):
				opts.PasswordsCSV = arg[len("--passwords="):]
			case arg == "--no-reconnect":
				opts.NoReconnect = true
			case arg == "--wingui":
				opts.Wingui = true
			case arg == "--gui-internal-home":
				opts.GuiInternalHome = true
			case arg == "--gui-internal-list" && i+1 < len(args):
				i++
				if args[i] == "" {
					return nil, fmt.Errorf("--gui-internal-list requires a directory")
				}
				opts.GuiInternalList = args[i]
			case strings.HasPrefix(arg, "--gui-internal-list="):
				value := arg[len("--gui-internal-list="):]
				if value == "" {
					return nil, fmt.Errorf("--gui-internal-list requires a directory")
				}
				opts.GuiInternalList = value
			case arg == "--rsync-upload" && i+1 < len(args):
				i++
				opts.RsyncUpload = args[i]
			case strings.HasPrefix(arg, "--rsync-upload="):
				opts.RsyncUpload = arg[len("--rsync-upload="):]
			case arg == "--rsync-download" && i+1 < len(args):
				i++
				opts.RsyncDownload = args[i]
			case strings.HasPrefix(arg, "--rsync-download="):
				opts.RsyncDownload = arg[len("--rsync-download="):]
			case arg == "--scp-upload" && i+1 < len(args):
				i++
				opts.ScpUpload = args[i]
			case strings.HasPrefix(arg, "--scp-upload="):
				opts.ScpUpload = arg[len("--scp-upload="):]
			case arg == "--scp-download" && i+1 < len(args):
				i++
				opts.ScpDownload = args[i]
			case strings.HasPrefix(arg, "--scp-download="):
				opts.ScpDownload = arg[len("--scp-download="):]
			case arg == "--ssh-gateway" && i+1 < len(args):
				i++
				opts.SSHGateway = args[i]
			case strings.HasPrefix(arg, "--ssh-gateway="):
				opts.SSHGateway = arg[len("--ssh-gateway="):]
			case arg == "--mosh":
				opts.Mosh = true
			case arg == "--mosh-session" && i+1 < len(args):
				i++
				opts.MoshSession = args[i]
			case strings.HasPrefix(arg, "--mosh-session="):
				opts.MoshSession = arg[len("--mosh-session="):]
			case arg == "--reconnect-delay" && i+1 < len(args):
				i++
				d := 0
				for _, c := range args[i] {
					if c >= '0' && c <= '9' {
						d = d*10 + int(c-'0')
					}
				}
				if d > 0 {
					opts.ReconnectDelay = d
				}
			case strings.HasPrefix(arg, "--reconnect-delay="):
				d := 0
				for _, c := range arg[len("--reconnect-delay="):] {
					if c >= '0' && c <= '9' {
						d = d*10 + int(c-'0')
					}
				}
				if d > 0 {
					opts.ReconnectDelay = d
				}
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

		// GOST-style single-dash URL flags: -dynamicproxy:// -ltcp:// -rtcp://
		if strings.HasPrefix(arg, "-dynamicproxy://") {
			val := arg[len("-dynamicproxy://"):]
			opts.DynamicForwards = append(opts.DynamicForwards, normalizeBind(val))
			i++
			continue
		}
		if strings.HasPrefix(arg, "-ltcp://") {
			val := arg[len("-ltcp://"):]
			for _, pair := range strings.Split(val, ",") {
				if pair != "" {
					opts.LocalForwards = append(opts.LocalForwards, normalizeTcpForward(pair))
				}
			}
			i++
			continue
		}
		if strings.HasPrefix(arg, "-rtcp://") {
			val := arg[len("-rtcp://"):]
			for _, pair := range strings.Split(val, ",") {
				if pair != "" {
					opts.RemoteForwards = append(opts.RemoteForwards, normalizeTcpForward(pair))
				}
			}
			i++
			continue
		}

		if arg[0] != '-' {
			if opts.Host == "" {
				// First positional arg is [user@]host
				opts.Host = arg
			} else if strings.Contains(arg, "@") {
				// Additional positional args with @ are extra hops
				opts.ExtraHosts = append(opts.ExtraHosts, arg)
			} else {
				// First arg without @ after hosts is the command
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

	// Parse user[:pass]@host[:port] for first host
	if opts.Host != "" && strings.Contains(opts.Host, "@") {
		hop, err := ParseHopSpec(opts.Host)
		if err != nil {
			// Fallback to simple user@host
			parts := strings.SplitN(opts.Host, "@", 2)
			opts.User = parts[0]
			opts.Host = parts[1]
		} else {
			opts.User = hop.User
			opts.Host = hop.Host
			if hop.Port != 22 && opts.Port == 0 {
				opts.Port = hop.Port
			}
			if hop.Password != "" && opts.Password == "" {
				opts.Password = hop.Password
			}
		}
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

	// --secondhostpass overrides inline password
	if opts.SecondHostPass != "" {
		opts.SecondHostPassword = opts.SecondHostPass
	}

	if err := validateGuiMode(opts); err != nil {
		return nil, err
	}
	if err := validateTransferMode(opts); err != nil {
		return nil, err
	}
	if err := validateGatewayMode(opts); err != nil {
		return nil, err
	}
	if err := validateMoshMode(opts); err != nil {
		return nil, err
	}

	return opts, nil
}

func validateGuiMode(opts *Options) error {
	if opts.Wingui && opts.HasGUIInternalMode() {
		return fmt.Errorf("--wingui cannot be combined with GUI internal flags")
	}
	if opts.Wingui {
		if opts.HasTransferMode() {
			return fmt.Errorf("--wingui cannot be combined with transfer flags")
		}
		if opts.Command != "" {
			return fmt.Errorf("--wingui cannot be combined with a remote command")
		}
		if opts.NoCommand {
			return fmt.Errorf("--wingui cannot be combined with -N")
		}
		if opts.StdioForward != "" {
			return fmt.Errorf("--wingui cannot be combined with -W")
		}
		if len(opts.LocalForwards) > 0 || len(opts.RemoteForwards) > 0 || len(opts.DynamicForwards) > 0 {
			return fmt.Errorf("--wingui cannot be combined with port forwarding")
		}
	}
	if !opts.HasGUIInternalMode() {
		return nil
	}
	if opts.GuiInternalHome && opts.GuiInternalList != "" {
		return fmt.Errorf("GUI internal flags are mutually exclusive")
	}
	if opts.HasTransferMode() {
		return fmt.Errorf("GUI internal mode cannot be combined with transfer flags")
	}
	if opts.Command != "" {
		return fmt.Errorf("GUI internal mode cannot be combined with a remote command")
	}
	if opts.NoCommand {
		return fmt.Errorf("GUI internal mode cannot be combined with -N")
	}
	if opts.StdioForward != "" {
		return fmt.Errorf("GUI internal mode cannot be combined with -W")
	}
	if len(opts.LocalForwards) > 0 || len(opts.RemoteForwards) > 0 || len(opts.DynamicForwards) > 0 {
		return fmt.Errorf("GUI internal mode cannot be combined with port forwarding")
	}
	return nil
}

func validateTransferMode(opts *Options) error {
	count := 0
	for _, value := range []string{
		opts.RsyncUpload,
		opts.RsyncDownload,
		opts.ScpUpload,
		opts.ScpDownload,
	} {
		if value != "" {
			count++
		}
	}
	if count > 1 {
		return fmt.Errorf("transfer flags are mutually exclusive")
	}
	if count == 0 {
		return nil
	}
	if opts.Command != "" {
		return fmt.Errorf("transfer mode cannot be combined with a remote command")
	}
	if opts.NoCommand {
		return fmt.Errorf("transfer mode cannot be combined with -N")
	}
	if opts.StdioForward != "" {
		return fmt.Errorf("transfer mode cannot be combined with -W")
	}
	if len(opts.LocalForwards) > 0 || len(opts.RemoteForwards) > 0 || len(opts.DynamicForwards) > 0 {
		return fmt.Errorf("transfer mode cannot be combined with port forwarding")
	}
	return nil
}

func validateGatewayMode(opts *Options) error {
	if opts.SSHGateway == "" {
		return nil
	}
	if opts.ForwardAgent {
		return fmt.Errorf("--ssh-gateway cannot be combined with -A")
	}
	if opts.ForwardX11 {
		return fmt.Errorf("--ssh-gateway cannot be combined with -X")
	}
	if opts.ForwardX11Trusted {
		return fmt.Errorf("--ssh-gateway cannot be combined with -Y")
	}
	if opts.NoCommand {
		return fmt.Errorf("--ssh-gateway cannot be combined with -N")
	}
	if opts.ForceTTY {
		return fmt.Errorf("--ssh-gateway cannot be combined with -t")
	}
	if opts.DisableTTY {
		return fmt.Errorf("--ssh-gateway cannot be combined with -T")
	}
	if opts.Subsystem {
		return fmt.Errorf("--ssh-gateway cannot be combined with -s")
	}
	if opts.StdioForward != "" {
		return fmt.Errorf("--ssh-gateway cannot be combined with -W")
	}
	if len(opts.LocalForwards) > 0 || len(opts.RemoteForwards) > 0 || len(opts.DynamicForwards) > 0 {
		return fmt.Errorf("--ssh-gateway cannot be combined with port forwarding (-L/-R/-D)")
	}
	if opts.Wingui {
		return fmt.Errorf("--ssh-gateway cannot be combined with --wingui")
	}
	if opts.HasGUIInternalMode() {
		return fmt.Errorf("--ssh-gateway cannot be combined with GUI internal flags")
	}
	if opts.HasTransferMode() {
		return fmt.Errorf("--ssh-gateway cannot be combined with transfer flags")
	}
	if opts.Command != "" {
		return fmt.Errorf("--ssh-gateway cannot be combined with a remote command")
	}
	return nil
}

func validateMoshMode(opts *Options) error {
	if opts.MoshSession != "" && !opts.Mosh {
		return fmt.Errorf("--mosh-session requires --mosh")
	}
	if !opts.Mosh {
		return nil
	}
	if opts.MoshSession != "" {
		if err := ValidateMoshSessionName(opts.MoshSession); err != nil {
			return err
		}
	}
	if opts.ForwardAgent {
		return fmt.Errorf("--mosh cannot be combined with -A")
	}
	if opts.ForwardX11 {
		return fmt.Errorf("--mosh cannot be combined with -X")
	}
	if opts.ForwardX11Trusted {
		return fmt.Errorf("--mosh cannot be combined with -Y")
	}
	if opts.NoCommand {
		return fmt.Errorf("--mosh cannot be combined with -N")
	}
	if opts.ForceTTY {
		return fmt.Errorf("--mosh cannot be combined with -t")
	}
	if opts.DisableTTY {
		return fmt.Errorf("--mosh cannot be combined with -T")
	}
	if opts.Subsystem {
		return fmt.Errorf("--mosh cannot be combined with -s")
	}
	if opts.StdioForward != "" {
		return fmt.Errorf("--mosh cannot be combined with -W")
	}
	if len(opts.LocalForwards) > 0 || len(opts.RemoteForwards) > 0 || len(opts.DynamicForwards) > 0 {
		return fmt.Errorf("--mosh cannot be combined with port forwarding (-L/-R/-D)")
	}
	if opts.Wingui {
		return fmt.Errorf("--mosh cannot be combined with --wingui")
	}
	if opts.HasGUIInternalMode() {
		return fmt.Errorf("--mosh cannot be combined with GUI internal flags")
	}
	if opts.HasTransferMode() {
		return fmt.Errorf("--mosh cannot be combined with transfer flags")
	}
	if opts.SSHGateway != "" {
		return fmt.Errorf("--mosh cannot be combined with --ssh-gateway")
	}
	if opts.Command != "" {
		return fmt.Errorf("--mosh cannot be combined with a remote command")
	}
	return nil
}

func ValidateMoshSessionName(name string) error {
	if name == "" {
		return fmt.Errorf("--mosh-session requires a name")
	}
	if len(name) > 64 {
		return fmt.Errorf("--mosh-session name is too long")
	}
	if name == "." || name == ".." {
		return fmt.Errorf("invalid --mosh-session name %q", name)
	}
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			continue
		}
		return fmt.Errorf("invalid --mosh-session name %q", name)
	}
	return nil
}

func (opts *Options) HasTransferMode() bool {
	return opts.RsyncUpload != "" || opts.RsyncDownload != "" || opts.ScpUpload != "" || opts.ScpDownload != ""
}

func (opts *Options) HasGUIInternalMode() bool {
	return opts.GuiInternalHome || opts.GuiInternalList != ""
}

// ParseHopSpec parses a "user[:pass]@host[:port]" string into a HopSpec.
// Supports the same escaping as --secondhost (backslash, single/double quotes).
func ParseHopSpec(spec string) (HopSpec, error) {
	hop := HopSpec{Port: 22}

	userPart, hostPart, err := splitOnUnescaped(spec, '@')
	if err != nil {
		return hop, fmt.Errorf("expected user[:pass]@host[:port], got %q", spec)
	}

	userName, password, hasPass := splitFirstUnescaped(userPart, ':')
	hop.User = unescapeStr(userName)
	if hasPass {
		hop.Password = unescapeStr(password)
	}

	if h, p, err := splitHostPort(hostPart); err == nil {
		hop.Host = h
		hop.Port = p
	} else {
		hop.Host = hostPart
	}

	if hop.Host == "" {
		return hop, fmt.Errorf("empty hostname in %q", spec)
	}
	if hop.User == "" {
		return hop, fmt.Errorf("empty user in %q", spec)
	}
	return hop, nil
}

// parseSecondHost parses "user:pass@host:port" into SecondHost* fields.
// Supports backslash escaping (\@ \: \\) and quoted passwords ("..." or '...').
func parseSecondHost(opts *Options) error {
	spec := opts.SecondHost

	// Find the split point between user:pass and host:port.
	// We need to find the last unescaped, unquoted '@'.
	userPart, hostPart, err := splitOnUnescaped(spec, '@')
	if err != nil {
		return fmt.Errorf("expected user[:pass]@host[:port], got %q", spec)
	}

	// Parse user:password from userPart.
	// Find first unescaped, unquoted ':' for user:pass separation.
	userName, password, hasPass := splitFirstUnescaped(userPart, ':')
	opts.SecondHostUser = unescapeStr(userName)
	if hasPass {
		opts.SecondHostPassword = unescapeStr(password)
	}

	// Parse host:port (no escaping needed here — host:port is simple)
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

// splitOnUnescaped splits s on the last occurrence of sep that is not
// inside quotes or preceded by a backslash.
func splitOnUnescaped(s string, sep byte) (left, right string, err error) {
	lastIdx := -1
	inSingle := false
	inDouble := false
	escaped := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if c == sep && !inSingle && !inDouble {
			lastIdx = i
		}
	}
	if lastIdx == -1 {
		return "", "", fmt.Errorf("separator '%c' not found", sep)
	}
	return s[:lastIdx], s[lastIdx+1:], nil
}

// splitFirstUnescaped splits s on the first unescaped/unquoted occurrence of sep.
// Returns (whole, "", false) if sep not found.
func splitFirstUnescaped(s string, sep byte) (left, right string, found bool) {
	inSingle := false
	inDouble := false
	escaped := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if c == sep && !inSingle && !inDouble {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// unescapeStr removes backslash escaping and all quote characters (single and
// double) from a string. It is intended for use with splitFirstUnescaped /
// splitOnUnescaped, which already handle quote-context-aware splitting; after
// splitting, the quote delimiters themselves are stripped here.
// Note: a literal quote inside a password must be backslash-escaped (e.g. \').
func unescapeStr(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			b.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		// Strip surrounding quotes
		if c == '"' || c == '\'' {
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// normalizeBind normalizes a bind address: "8080" | ":8080" | "host:8080" → "host:8080"
func normalizeBind(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	// Already host:port?
	if strings.Contains(s, ":") {
		if s[0] == ':' {
			return "127.0.0.1" + s
		}
		return s
	}
	// Just a port number
	return "127.0.0.1:" + s
}

// normalizeHostPort normalizes host:port|:port|port with a default host
func normalizeHostPort(s, defaultHost string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if strings.Contains(s, ":") {
		if s[0] == ':' {
			return defaultHost + s
		}
		return s
	}
	return defaultHost + ":" + s
}

// normalizeTcpForward converts "listenAddr/targetAddr" into
// the colon-separated format expected by -L/-R: "bindHost:bindPort:targetHost:targetPort"
func normalizeTcpForward(spec string) string {
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 {
		return spec // pass through, will fail later with parse error
	}
	listen := normalizeHostPort(parts[0], "127.0.0.1")
	target := normalizeHostPort(parts[1], "127.0.0.1")
	// listen = "host:port", target = "host:port"
	// -L/-R expects "bindHost:bindPort:targetHost:targetPort"
	return listen + ":" + target
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
