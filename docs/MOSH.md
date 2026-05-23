# FlySSH Mosh Mode

`flyssh ... --mosh` starts an interactive mosh-style terminal session over the
same FlySSH route that a normal shell would use. It is designed for networks
where direct UDP to the final server is blocked by firewalls, SOCKS-only access,
or multi-hop jump hosts.

## What It Optimizes

- **No direct UDP requirement**: mosh datagrams are carried inside FlySSH's SSH
  chain instead of being sent directly to the final server's UDP port.
- **Current route reuse**: SOCKS proxy, unlimited positional hops,
  `--passwords`, `--keys`, `-i`, host-key handling, and keepalive all reuse the
  existing FlySSH connection code.
- **No external mosh binaries**: the local side uses FlySSH plus the
  FlySSH-maintained `github.com/lovitus/mosh-go` fork. The remote side uses the
  embedded FlySSH relay helper.
- **Interactive resilience**: when the outer SSH chain drops inside the same
  FlySSH process, the local mosh client state is kept and only the SSH chain plus
  attach pipe are rebuilt.
- **Optional persistent remote session**: `--mosh-session NAME` can take over an
  existing remote PTY/shell from a new FlySSH process with a fresh key.

This is a terminal feature only. It does not replace FlySSH's SCP, rsync,
gateway, or forwarding modes.

## Basic Usage

```bash
# Single host
flyssh user:password@host --mosh

# SOCKS + multi-hop
flyssh --socks 127.0.0.1:1080 user1@hop1 user2@target \
  --passwords 'hop1pass,targetpass' --mosh

# Named session for cross-process reattach
flyssh user:password@host --mosh --mosh-session work
```

During startup, SSH authentication, host-key prompts, passphrases, and MFA still
use the normal terminal. FlySSH switches stdin to raw mode only after remote
start and attach have succeeded.

## Parameters

### `--mosh`

Starts the built-in mosh-over-FlySSH terminal mode. It requires a normal FlySSH
host or hop chain. The final hop becomes the remote shell host.

Allowed with:

- route/auth options such as `--socks`, positional hops, `--password`,
  `--passwords`, `--keys`, `-i`, `-F`, `-J`, and `-o`
- `--reconnect-delay N`, which controls the delay before retrying the outer SSH
  attach after it disconnects

Mosh mode uses its own reconnect loop so the local mosh client can stay alive
while the outer SSH chain is rebuilt. `--reconnect-delay` is honored by this
loop. `--no-reconnect` is not a mosh-mode control knob.

Rejected with:

- remote command arguments
- transfer flags: `--scp-*`, `--rsync-*`
- `--wingui`
- `--ssh-gateway`
- port forwarding: `-L`, `-R`, `-D`
- `-N`, `-W`, `-s`, `-t`, `-T`, `-A`, `-X`, `-Y`

### `--mosh-session NAME`

Names the remote mosh daemon session. Use it when you want a later FlySSH
process to reattach to the same remote PTY/shell.

Name rules:

- length: 1 to 64 characters
- allowed characters: `A-Z`, `a-z`, `0-9`, `.`, `_`, `-`
- rejected names include empty string, `.`, `..`, spaces, `/`, `\`, `~`, and
  non-ASCII path-like names

Without `--mosh-session`, FlySSH creates a random session name. That is good for
normal one-off use and same-process reconnect, but it cannot be guessed by a new
FlySSH process for cross-process reattach.

## Reconnect and Reattach Semantics

There are two different recovery paths:

### Same FlySSH Process

If the outer SSH chain drops while the FlySSH process is still running:

1. the local mosh client and transport state stay alive
2. FlySSH waits `--reconnect-delay` seconds, default `3`
3. FlySSH rebuilds the SSH/SOCKS/multi-hop chain
4. FlySSH starts a new remote `-mosh-attach` helper
5. the same local mosh session continues

This path does not perform takeover and does not generate a new mosh key.

### New FlySSH Process With `--mosh-session`

If the local process exits but the remote daemon is still alive:

1. run FlySSH again with the same `--mosh-session NAME`
2. remote relay finds the existing session socket
3. daemon prepares a takeover and returns a fresh mosh key plus a short-lived
   takeover token
4. local FlySSH creates a fresh mosh client with the new key
5. attach commits the takeover
6. the old local client, if still present, becomes invalid

This fresh-key takeover is required by mosh/SSP replay protection. A brand-new
client cannot safely reuse an old key and transport association.

Remote sessions use a 14-day idle network timeout. This is intentionally long so
that a named session can survive extended network loss. If the remote daemon has
exited, FlySSH reports an attach/start error instead of silently resuming a dead
PTY.

## Implementation Details

### Local Side

`main.go` handles `--mosh` before the normal reconnect loop. `runMosh` builds a
connector around the existing `connectChain` function, so every reconnect uses
the same FlySSH route and authentication behavior.

`pkg/moshsession` owns the local mosh session:

- starts the remote daemon with `flyssh-relay -mosh-start`
- attaches with `flyssh-relay -mosh-attach`
- wraps the SSH attach stream in a datagram `tunnelConn`
- feeds that connection to `mosh.DialConn`
- copies local stdin to `mosh.Client.Send`
- copies `mosh.Client.Recv` output to stdout
- polls terminal resize and sends resize instructions
- keeps raw terminal mode active for the duration of the mosh session

The SSH attach stream uses length-prefixed datagram frames:

```text
uint32 big-endian length + payload
```

Frames are bounded by `pkg/moshframe` and are not shell text.

### Remote Side

The embedded relay supports three internal commands on Linux, Darwin, and
FreeBSD targets:

- `-mosh-start SESSION`
- `-mosh-attach SESSION [TAKEOVER_TOKEN]`
- `-mosh-daemon SESSION`

`-mosh-start` ensures the relay binary is present on the final host, creates or
finds the session, and prints JSON containing:

- `session_id`
- `key`
- `socket_path`
- `pid`
- `took_over`
- `takeover_token`, when takeover is needed

The daemon:

- starts detached with `setsid`
- redirects stdin/stdout/stderr to `/dev/null`
- creates `/tmp/flyssh-mosh-$UID` with mode `0700`
- creates a session Unix socket with mode `0600`
- writes session metadata next to the socket
- runs a `mosh-go` server against an injected packet connection
- keeps one active attach pipe and replaces the old attach when a new one
  succeeds

Remote Windows is not supported for the mosh daemon because this path depends on
Unix PTYs and Unix domain sockets.

### `mosh-go` Fork

FlySSH depends on `github.com/lovitus/mosh-go`. The fork is based on upstream
`github.com/unixshells/mosh-go v0.5.2` and carries FlySSH-specific tags such as
`v0.5.2-flyssh.9`.

Important fork changes include:

- authenticated receive result, so unauthenticated UDP/datagram input cannot
  update roaming state
- fragment accounting fixes
- injected `PacketConn` server transport
- staged takeover API
- terminal query response forwarding, so programs waiting for `ESC[6n` do not
  block the server event loop
- framebuffer diff fixes for stale row fragments, alternate screen transitions,
  application cursor-key mode, and application keypad mode

FlySSH releases must depend on an actual fork tag. Release builds must not rely
on a local `replace`.

## Differences From Standard Mosh

| Area | Standard mosh | FlySSH `--mosh` |
|---|---|---|
| Startup | SSH starts `mosh-server` | FlySSH starts embedded relay `-mosh-start` |
| Data path | Direct UDP between client and server | Length-framed datagrams through FlySSH SSH chain |
| UDP exposure | Remote UDP port must be reachable | No remote UDP port needs to be reachable |
| Network roaming | Client can move between IPs via UDP | Outer SSH chain reconnects, then reattaches |
| External binaries | Requires `mosh-client` locally and `mosh-server` remotely | Uses FlySSH binary and embedded relay |
| Cross-process resume | Native mosh client/server state | Explicit `--mosh-session NAME` takeover with a fresh key |
| Protocol implementation | Mature C mosh | FlySSH-maintained Go fork of `mosh-go` |
| Remote platforms | Platforms supported by official mosh | Linux/Darwin/FreeBSD relay targets only |

FlySSH's mode is not a transparent bridge for the standard `mosh-client` command.
It is an integrated terminal mode inside FlySSH.

## Not Implemented

- non-interactive remote commands under `--mosh`
- SCP/SFTP/rsync in mosh mode
- local, remote, or dynamic port forwarding in mosh mode
- X11 forwarding
- SSH agent forwarding
- remote Windows mosh daemon
- direct compatibility with external `mosh-client` or `mosh-server`
- exposing a raw UDP listener for other clients
- user-configurable idle timeout; current remote daemon timeout is 14 days

Use normal FlySSH shell, transfer, forwarding, `--wingui`, or `--ssh-gateway`
for those workflows.

## Operational Notes

- Keep the launching terminal open. It carries prompts before raw mode and the
  interactive terminal after attach.
- If testing a new FlySSH release with a fixed `--mosh-session`, start with a new
  session name or remove the old remote session. Existing daemons keep running
  old relay code until they exit.
- If the session appears stale, check `/tmp/flyssh-mosh-$UID` on the remote host.
  The socket, lock, and JSON metadata are stored there.
- Use `-v` to see relay upload/cache and reconnect information.
