# FlySsh

A full-featured SSH client written in Go, with native **SOCKS5 proxy** support — no need for Proxifier, iptables, or `ProxyCommand` hacks.

## Why?

Standard OpenSSH clients cannot natively connect through a SOCKS5 proxy. You typically need external tools like Proxifier, `tsocks`, or `connect-proxy` via `ProxyCommand`. FlySsh solves this by building SOCKS5 support directly into the client while maintaining full compatibility with OpenSSH's feature set.

## Features

| Feature | Flag | Description |
|---|---|---|
| **SOCKS5 Proxy** | `--socks host:port` | Connect through a SOCKS5 proxy (with optional auth) |
| Public Key Auth | `-i keyfile` | Identity file authentication |
| Password Auth | (interactive) | Prompted when needed |
| SSH Agent | `-A` | Agent forwarding |
| Local Forward | `-L [bind:]port:host:port` | Local port forwarding |
| Remote Forward | `-R [bind:]port:host:port` | Remote port forwarding |
| Dynamic Forward | `-D [bind:]port` | SOCKS5 dynamic proxy via SSH tunnel |
| ProxyJump | `-J user@host:port` | Multi-hop jump hosts |
| Stdio Forward | `-W host:port` | Forward stdin/stdout to remote host:port |
| PTY Control | `-t` / `-T` | Force or disable pseudo-terminal |
| SSH Config | `-F configfile` | Parse `~/.ssh/config` |
| Compression | `-C` | Enable compression |
| Subsystem | `-s` | Request subsystem (e.g., sftp) |
| Keepalive | `-o ServerAliveInterval=N` | Periodic keepalive |
| Known Hosts | auto | Reads `~/.ssh/known_hosts`, prompts for unknown |

## Installation

```bash
go install github.com/flyssh/flyssh@latest
```

Or build from source:

```bash
git clone https://github.com/flyssh/flyssh.git
cd flyssh
go build -o flyssh .
```

## Usage

### Basic connection
```bash
flyssh user@hostname
flyssh -p 2222 user@hostname
```

### Connect through SOCKS5 proxy
```bash
# Connect to SSH server via SOCKS5 proxy
flyssh --socks 127.0.0.1:1080 user@hostname

# With SOCKS5 authentication
flyssh --socks 127.0.0.1:1080 --socks-user myuser --socks-pass mypass user@hostname
```

### Port forwarding through SOCKS5
```bash
# Local port forwarding via SOCKS5 proxy
flyssh --socks 127.0.0.1:1080 -L 8080:internal-host:80 -N user@hostname

# Dynamic SOCKS proxy through SSH tunnel (via SOCKS5 proxy)
flyssh --socks 127.0.0.1:1080 -D 1081 -N user@hostname

# Remote port forwarding
flyssh --socks 127.0.0.1:1080 -R 9090:localhost:3000 -N user@hostname
```

### Jump hosts (ProxyJump)
```bash
# Single jump
flyssh -J jumpuser@jumphost user@target

# Chain multiple jumps
flyssh -J jump1@host1,jump2@host2 user@target

# Jump host through SOCKS5
flyssh --socks 127.0.0.1:1080 -J jumpuser@jumphost user@target
```

### Execute remote commands
```bash
flyssh user@hostname "ls -la /tmp"
flyssh -t user@hostname "top"  # Force PTY for interactive commands
```

### Stdio forwarding
```bash
flyssh -W internal-host:22 user@gateway  # Pipe SSH through gateway
```

### Use specific identity file
```bash
flyssh -i ~/.ssh/my_key user@hostname
```

## SSH Config Support

FlySsh reads `~/.ssh/config` automatically. Example:

```
Host myserver
    HostName 192.168.1.100
    User admin
    Port 2222
    IdentityFile ~/.ssh/id_ed25519
    ProxyJump jump@gateway.example.com
    ForwardAgent yes
    ServerAliveInterval 60
    ServerAliveCountMax 3
```

Then simply: `flyssh --socks 127.0.0.1:1080 myserver`

## SOCKS5 Proxy Options

| Flag | Description |
|---|---|
| `--socks host:port` | SOCKS5 proxy address |
| `--socks-user username` | SOCKS5 username (optional) |
| `--socks-pass password` | SOCKS5 password (optional) |

The SOCKS5 proxy is used for the initial TCP connection to the SSH server (or the first jump host). All SSH protocol features (port forwarding, etc.) work normally on top of this tunneled connection.

## All Options

```
flyssh [options] [user@]hostname [command ...]

  -4              Force IPv4
  -6              Force IPv6
  -A              Enable agent forwarding
  -a              Disable agent forwarding
  -b bind_addr    Bind address
  -C              Enable compression
  -c cipher       Cipher specification
  -D [bind:]port  Dynamic port forwarding (SOCKS5)
  -E log_file     Log file
  -e char         Escape character (default: ~)
  -F config       SSH config file
  -f              Background after auth
  -g              Allow remote connects to forwarded ports
  -i identity     Identity file (private key)
  -J destination  ProxyJump
  -L spec         Local port forwarding
  -l login_name   Login name
  -m mac_spec     MAC specification
  -N              No remote command (forwarding only)
  -o option       SSH option (key=value)
  -p port         Port (default: 22)
  -q              Quiet mode
  -R spec         Remote port forwarding
  -s              Subsystem request
  -T              Disable pseudo-terminal
  -t              Force pseudo-terminal
  -V              Show version
  -v              Verbose mode
  -W host:port    Stdio forwarding
  -X              X11 forwarding
  -Y              Trusted X11 forwarding
  --socks addr    SOCKS5 proxy server
  --socks-user u  SOCKS5 username
  --socks-pass p  SOCKS5 password
```

## License

MIT
