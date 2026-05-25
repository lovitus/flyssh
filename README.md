# FlySsh

**A portable, single-binary SSH client with built-in SOCKS5 proxy, unlimited multi-hop chaining, multiplexed relay tunneling, and auto-reconnect.**

**便携式单文件 SSH 客户端，内置 SOCKS5 代理、无限多跳链接、复用隧道转发、自动重连。**

---

## Why FlySsh? / 为什么用 FlySsh？

OpenSSH cannot natively connect through a SOCKS5 proxy — you need Proxifier, `tsocks`, or `ProxyCommand` hacks. FlySsh builds SOCKS5 support directly into the client. It also solves common pain points when working with multi-hop SSH tunnels behind restrictive firewalls.

OpenSSH 无法原生通过 SOCKS5 代理连接，通常需要借助 Proxifier、`tsocks` 或 `ProxyCommand`。FlySsh 将 SOCKS5 支持直接内建到客户端中，同时解决了在限制性防火墙后进行多跳 SSH 隧道时的常见痛点。

### Key advantages / 核心优势

- **SOCKS5 built-in** — no external proxy tools needed / 内置 SOCKS5，无需外部工具
- **Unlimited multi-hop** — chain through N machines with one command / 一条命令穿透 N 台机器
- **Multiplexed relay** — bypasses `MaxSessions` limits, all forwards over 1 SSH session / 复用中继绕过 MaxSessions 限制
- **Hash-based relay caching** — relay binary uploaded once per hash, skips re-upload / 基于哈希缓存，中继只上传一次
- **Built-in file transfer modes** — native `scp` and managed `rsync` over the same route / 内置文件传输模式，支持原生 `scp` 和托管 `rsync`
- **Auto-reconnect** — reconnects on connection loss when credentials are non-interactive / 非交互凭据下自动重连
- **Idle timeout** — inactive forwarded connections auto-close after 5 minutes / 空闲连接 5 分钟自动关闭
- **Single binary** — no dependencies, cross-platform (Windows/Linux/macOS, amd64/arm64) / 单文件无依赖，跨平台

---

## Installation / 安装

### Package managers / 包管理器

FlySsh keeps Homebrew tap and Scoop bucket files in this repository. No extra
packaging repository is required.

FlySsh 的 Homebrew tap 和 Scoop bucket 文件直接放在本仓库中，不需要额外维护包管理仓库。

#### Scoop (Windows)

```powershell
scoop bucket add flyssh https://github.com/lovitus/flyssh
scoop install flyssh

# Update later / 后续更新
scoop update flyssh
```

#### Homebrew (macOS/Linux)

```bash
brew tap lovitus/flyssh https://github.com/lovitus/flyssh
brew install flyssh

# Update later / 后续更新
brew update
brew upgrade flyssh
```

Because this repository is not named `homebrew-flyssh`, include the repository
URL when running `brew tap`.

由于本仓库名不是 `homebrew-flyssh`，执行 `brew tap` 时需要带上仓库 URL。

#### APT (Debian/Ubuntu amd64/arm64)

```bash
arch="$(dpkg --print-architecture)"
case "$arch" in amd64|arm64) ;; *) echo "unsupported APT arch: $arch" >&2; exit 1;; esac
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://lovitus.github.io/flyssh/apt/flyssh-archive-keyring.gpg \
  | sudo tee /etc/apt/keyrings/flyssh-archive-keyring.gpg >/dev/null
echo "deb [arch=$arch signed-by=/etc/apt/keyrings/flyssh-archive-keyring.gpg] https://lovitus.github.io/flyssh/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/flyssh.list >/dev/null
sudo apt update
sudo apt install flyssh

# Update later / 后续更新
sudo apt update
sudo apt upgrade flyssh
```

#### RPM/YUM/DNF (x86_64/aarch64)

```bash
sudo tee /etc/yum.repos.d/flyssh.repo >/dev/null <<'EOF'
[flyssh]
name=FlySSH stable repository
baseurl=https://lovitus.github.io/flyssh/rpm/$basearch
enabled=1
repo_gpgcheck=1
gpgcheck=0
gpgkey=https://lovitus.github.io/flyssh/rpm/RPM-GPG-KEY-flyssh
EOF

sudo dnf install flyssh
# or: sudo yum install flyssh

# Update later / 后续更新
sudo dnf upgrade flyssh
# or: sudo yum upgrade flyssh
```

The RPM repository signs repository metadata (`repomd.xml`) in v1. Individual
RPM packages are not signed yet, so the repo file intentionally uses
`repo_gpgcheck=1` and `gpgcheck=0`.

RPM 源 v1 签名的是仓库 metadata（`repomd.xml`），暂不对单个 RPM 包签名，因此
repo 配置中使用 `repo_gpgcheck=1` 和 `gpgcheck=0`。

### Pre-built binaries / 预编译二进制

Download from [Releases](https://github.com/lovitus/flyssh/releases).

| Platform | Binary |
|---|---|
| Windows amd64 | `flyssh-windows-amd64.exe` |
| Windows arm64 | `flyssh-windows-arm64.exe` |
| Linux amd64 | `flyssh-linux-amd64` |
| Linux arm64 | `flyssh-linux-arm64` |
| macOS Intel | `flyssh-darwin-amd64` |
| macOS Apple Silicon | `flyssh-darwin-arm64` |

### Build from source / 从源码构建

```bash
git clone https://github.com/lovitus/flyssh.git
cd FlySsh
go build -o flyssh .

# Or full cross-platform build (PowerShell):
# 或完整跨平台构建 (PowerShell)：
.\build.ps1
```

---

## Quick Start / 快速开始

```bash
# Basic connection / 基本连接
flyssh user@hostname
flyssh user:password@hostname

# Through SOCKS5 proxy / 通过 SOCKS5 代理
flyssh --socks 127.0.0.1:1080 user@hostname

# Multi-hop chain / 多跳链接
flyssh user1:pass1@hop1 user2:pass2@hop2 user3@hop3:2222

# Port forwarding on last hop / 在最后一跳上端口转发
flyssh user1:p1@hop1 user2:p2@hop2 -ltcp://:8080/127.0.0.1:80

# Mosh-style terminal over the same route, no remote UDP reachability needed
# 通过同一条链路运行 mosh 风格终端，不要求远端 UDP 可直连
flyssh --socks 127.0.0.1:1080 user1@hop1 user2@target --passwords 'p1,p2' --mosh
```

## Validation Report / 验证报告

Live transfer validation notes for the current implementation are recorded in [VALIDATION_REPORT_2026-04-05.md](./VALIDATION_REPORT_2026-04-05.md).

---

## Features / 功能列表

| Feature / 功能 | Flag / 参数 | Description / 说明 |
|---|---|---|
| SOCKS5 Proxy / 代理 | `--socks host:port` | Connect through SOCKS5 / 通过 SOCKS5 连接 |
| Multi-hop / 多跳 | positional args | Unlimited hop chaining / 无限跳数链接 |
| Inline credentials / 内联凭据 | `user:pass@host:port` | Password in connection string / 连接串中传密码 |
| Per-hop keys / 逐跳密钥 | `--keys "k1,,k3"` | Comma-separated per-hop keys / 逗号分隔逐跳密钥 |
| Per-hop passwords / 逐跳密码 | `--passwords "p1,,p3"` | Comma-separated per-hop passwords / 逗号分隔逐跳密码 |
| Local forward / 本地转发 | `-L` or `-ltcp://` | Local port forwarding / 本地端口转发 |
| Remote forward / 远程转发 | `-R` or `-rtcp://` | Remote port forwarding / 远程端口转发 |
| Dynamic forward / 动态转发 | `-D` | SOCKS5 proxy via SSH / 通过 SSH 的 SOCKS5 代理 |
| Mux relay / 复用中继 | automatic | 1 session for all forwards / 所有转发共用 1 个会话 |
| Auto-reconnect / 自动重连 | default on | Reconnects on connection loss / 断线自动重连 |
| SSH Agent | `-A` | Agent forwarding / 代理转发 |
| ProxyJump | `-J` | Standard jump host / 标准跳板机 |
| SSH Config | `-F` | Reads `~/.ssh/config` / 读取 SSH 配置 |
| Keepalive / 保活 | `-o ServerAliveInterval=N` | Periodic keepalive / 定期保活 |
| Stdio forward / 标准流转发 | `-W host:port` | Forward stdin/stdout / 转发标准输入输出 |
| Compression / 压缩 | `-C` | Enable compression / 启用压缩 |
| Rsync upload / 上传 | `--rsync-upload '...'` | Managed rsync upload on current route / 使用当前链路执行 rsync 上传 |
| Rsync download / 下载 | `--rsync-download '...'` | Managed rsync download on current route / 使用当前链路执行 rsync 下载 |
| SCP upload / 上传 | `--scp-upload '...'` | Built-in SCP upload on current route / 使用当前链路执行内置 SCP 上传 |
| SCP download / 下载 | `--scp-download '...'` | Built-in SCP download on current route / 使用当前链路执行内置 SCP 下载 |
| Windows transfer GUI / Windows 图形传输 | `--wingui` | Companion transfer panel for current route / 当前链路的图形传输面板 |
| SSH Gateway / SSH 网关 | `--ssh-gateway 'user:pass@bind:port'` | Proxy third-party SSH/SFTP clients through current route / 将第三方 SSH/SFTP 客户端通过当前链路代理 |
| Mosh terminal / Mosh 终端 | `--mosh` | Interactive mosh-style terminal over current route / 通过当前链路承载交互式 mosh 风格终端 |
| Mosh named session / Mosh 固定会话 | `--mosh-session NAME` | Reattach/create persistent remote PTY / 接回或创建持久远端 PTY |
| Host key auto-accept / 自动接受指纹 | default | Auto-accept new fingerprints / 自动接受新指纹 |

---

## Usage / 用法

### Basic Connection / 基本连接

```bash
flyssh user@hostname
flyssh user:password@hostname
flyssh -p 2222 user@hostname
flyssh user@hostname "ls -la"

# Use -- when the remote command contains @ or could look like another hop.
# 当远程命令包含 @ 或可能被误判为另一跳时，用 -- 分隔命令。
flyssh user@hostname -- "printf '%s\n' 'name@example.com'"
```

### SOCKS5 Proxy / SOCKS5 代理

```bash
flyssh --socks 127.0.0.1:1080 user@hostname

# With SOCKS5 auth / 带 SOCKS5 认证
flyssh --socks 127.0.0.1:1080 --socks-user myuser --socks-pass mypass user@hostname
```

### Multi-Hop Chaining / 多跳链接

Chain through unlimited machines. Each positional arg with `@` is a hop. The last hop gets the shell and port forwarding.

无限多跳链接。每个含 `@` 的位置参数就是一跳，最后一跳获得 shell 和端口转发。

```bash
# 2-hop: local → hop1 → hop2 (shell)
flyssh user1:pass1@hop1 user2:pass2@hop2

# 3-hop with port: local → hop1 → hop2 → hop3:2222 (shell)
flyssh user1:p1@hop1 user2:p2@hop2 user3:p3@hop3:2222

# Run command on last hop / 在最后一跳执行命令
flyssh user1:p1@hop1 user2:p2@hop2 "uname -a"
```

### Per-Hop Credentials / 逐跳凭据

```bash
# Inline passwords / 内联密码
flyssh user1:pass1@hop1 user2:pass2@hop2

# --passwords flag (comma-separated, empty = skip)
# --passwords 参数（逗号分隔，空 = 跳过）
flyssh user1@hop1 user2@hop2 user3@hop3 --passwords "pass1,,pass3"

# --keys flag (comma-separated, empty = skip)
# --keys 参数（逗号分隔，空 = 跳过）
flyssh user1@hop1 user2@hop2 user3@hop3 --keys "/path/key1,,/path/key3"

# Single key for all hops / 所有跳用同一密钥
flyssh user1@hop1 user2@hop2 -i ~/.ssh/id_rsa

# Mix inline + flags / 混合使用
flyssh user1:pass1@hop1 user2@hop2 --keys ",/path/key2"
```

### Password Escaping / 密码转义

If passwords contain `@` or `:`, use escaping:

如果密码包含 `@` 或 `:`，使用转义：

```bash
# Backslash / 反斜杠
flyssh user:p\@ss\:word@hostname

# Quotes / 引号
flyssh 'user:"p@ss:word"@hostname'
```

### Port Forwarding / 端口转发

```bash
# Standard OpenSSH syntax / 标准 OpenSSH 语法
flyssh user@host -L 8080:remote:80 -N
flyssh user@host -R 9090:localhost:3000 -N
flyssh user@host -D 1081 -N

# GOST-style easy syntax (supports multiple pairs with comma)
# GOST 风格简易语法（逗号分隔支持多组）
flyssh user@host -ltcp://:8080/remote:80
flyssh user@host -rtcp://:9090/localhost:3000
flyssh user@host -dynamicproxy://1081

# Multiple forwards in one flag / 一个参数多组转发
flyssh user@host -ltcp://:8080/remote:80,:2222/internal:22,:3306/db:3306

# Multi-hop + forwarding / 多跳 + 转发
flyssh u1:p1@hop1 u2:p2@hop2 -ltcp://:5001/127.0.0.1:5000,:5002/192.168.1.100:5000
```

### Auto-Reconnect / 自动重连

Enabled by default when non-interactive credentials are provided (password, key, etc.).

当提供非交互式凭据时默认启用（密码、密钥等）。

```bash
# Auto-reconnects on disconnect / 断线自动重连
flyssh user:password@hostname -ltcp://:8080/remote:80

# Disable / 禁用
flyssh user:password@hostname --no-reconnect

# Custom delay / 自定义延迟
flyssh user:password@hostname --reconnect-delay 10
```

### Reconnect Semantics / 重连语义

- In interactive shell mode, reconnect creates a fresh shell session.  
  交互 shell 模式下，重连后会创建新的 shell 会话。
- In command mode (`flyssh host "cmd"`), a reconnect re-runs the command.  
  命令模式（`flyssh host "cmd"`）下，重连会重新执行该命令。
- If you need strict one-shot command behavior, disable reconnect with `--no-reconnect`.  
  如果命令必须严格“一次执行”，请加 `--no-reconnect`。

### File Transfer / 文件传输

FlySsh now supports two explicit transfer modes:

FlySsh 现在支持两类显式文件传输模式：

- `--scp-upload '...'` / `--scp-download '...'`
- `--rsync-upload '...'` / `--rsync-download '...'`

Rules:

规则：

- exactly one transfer flag can be used in a command / 一次命令只能使用一个传输参数
- transfer mode cannot be combined with remote command, `-N`, `-W`, or any `-L/-R/-D` forwarding / 传输模式不能与远程命令、`-N`、`-W` 或 `-L/-R/-D` 转发混用
- transfer mode reuses outer FlySsh route/auth settings (SOCKS, multi-hop, `--passwords`, keys) / 传输模式复用外层 FlySsh 链路与认证（SOCKS、多跳、`--passwords`、密钥）
- for negative auth tests, add `--no-reconnect` to avoid retry loops / 做认证失败测试时建议加 `--no-reconnect` 防止自动重试
- Windows users can launch a companion transfer panel with `--wingui`; prompts still happen in the terminal / Windows 用户可以用 `--wingui` 打开图形传输面板；认证提示仍在终端完成

Examples:

示例：

```bash
# SCP upload / download（单跳）
flyssh user:pass@host --scp-upload './build/app.tar.gz /tmp/app.tar.gz'
flyssh user:pass@host --scp-download '/var/log/app.log ./logs/'

# SCP over multi-hop / 多跳 SCP
flyssh u1@hop1 u2@hop2 --passwords 'p1,p2' --scp-upload './a.txt /tmp/a.txt'

# rsync upload / download
flyssh user:pass@host --rsync-upload '-avz ./site/ /srv/site/'
flyssh user:pass@host --rsync-download '-avz /srv/site/ ./site-copy/'

# rsync over multi-hop + SOCKS
flyssh --socks 127.0.0.1:1080 u1@hop1 u2@hop2 --passwords 'p1,p2' \
  --rsync-upload '-av ./src/ /data/src/'
```

### SSH Gateway / SSH 网关

`--ssh-gateway 'user:pass@bind:port'` starts a local SSH server that proxies third-party SSH/SFTP clients (Xshell, SecureCRT, FileZilla, etc.) through FlySsh's established multi-hop connection to the final server. The third-party client authenticates with the local gateway credentials; FlySsh handles everything beyond.

`--ssh-gateway 'user:pass@bind:port'` 启动一个本地 SSH 服务，将第三方 SSH/SFTP 客户端（Xshell、SecureCRT、FileZilla 等）通过 FlySsh 已建立的多跳连接代理到目标服务器。第三方客户端只需对本地网关认证，FlySsh 负责其余所有链路。

```bash
# Start gateway: third-party clients connect to 127.0.0.1:2222 with admin/mypass
# 启动网关：第三方客户端用 admin/mypass 连接 127.0.0.1:2222
flyssh --socks 127.0.0.1:1080 user1@hop1 user2@target --ssh-gateway 'admin:mypass@127.0.0.1:2222'

# Then from any SSH client on the same machine / 同机上任意 SSH 客户端：
ssh -p 2222 admin@127.0.0.1
sftp -P 2222 admin@127.0.0.1
```

The gateway host key is persisted to `os.UserConfigDir()/flyssh/gateway_host_key` so clients do not see a key-changed warning on restart. Supported: shell, exec, pty, SFTP/SCP (subsystem/exec), client local port forward (-L), dynamic forward (-D). Not supported: remote port forward (-R), X11, agent forwarding.

网关主机密钥持久化到 `os.UserConfigDir()/flyssh/gateway_host_key`，重启不会触发客户端的主机密钥变更警告。支持：shell、exec、pty、SFTP/SCP（subsystem/exec）、客户端本地端口转发（-L）、动态转发（-D）。不支持：远程端口转发（-R）、X11、代理转发。

### Mosh over FlySSH / 通过 FlySSH 承载 Mosh

`--mosh` starts an interactive mosh-style terminal session over the current FlySsh route. Unlike standard mosh, the final server does not need to expose or receive direct UDP; FlySsh carries mosh datagrams through the existing SSH/SOCKS/multi-hop chain and the embedded relay helper.

`--mosh` 会通过当前 FlySsh 链路启动一个交互式 mosh 风格终端。与标准 mosh 不同，最终服务器不需要开放或接收直连 UDP；FlySsh 会把 mosh datagram 封装进现有 SSH/SOCKS/多跳链路和内嵌 relay helper。

```bash
# Single host / 单跳
flyssh user:pass@host --mosh

# SOCKS + multi-hop / SOCKS + 多跳
flyssh --socks 127.0.0.1:1080 user1@hop user2@target \
  --passwords 'hopPass,targetPass' --mosh

# Named session: later runs with the same name can take over the same remote PTY
# 固定会话：之后用同名 session 可接回同一个远端 PTY
flyssh user:pass@host --mosh --mosh-session work
```

Use `--mosh-session NAME` only when you want cross-process reattach. Names must be 1-64 characters and may contain only letters, digits, `.`, `_`, and `-`. Without it, FlySsh uses a random session name, which is best for one-off sessions and same-process reconnect.

只有需要跨进程接回时才使用 `--mosh-session NAME`。名称长度 1-64，只允许字母、数字、`.`、`_`、`-`。不指定时 FlySsh 使用随机会话名，适合一次性会话和同进程断线重连。

Mosh mode is terminal-only. It cannot be combined with remote commands, SCP/rsync transfer flags, `--wingui`, `--ssh-gateway`, `-L/-R/-D`, `-N`, `-W`, `-s`, `-t/-T`, `-A`, `-X`, or `-Y`.

Mosh 模式只用于交互式终端，不能与远程命令、SCP/rsync 传输参数、`--wingui`、`--ssh-gateway`、`-L/-R/-D`、`-N`、`-W`、`-s`、`-t/-T`、`-A`、`-X`、`-Y` 混用。

More details, including differences from standard mosh and implementation notes, are in [docs/MOSH.md](./docs/MOSH.md).

更多设计差异、未实现范围和实现细节见 [docs/MOSH.md](./docs/MOSH.md)。

### Windows companion GUI / Windows 图形传输面板

`--wingui` opens a Windows-only companion panel for the current FlySsh route. It reuses the connection arguments already provided on the command line and starts child `flyssh.exe` processes for browsing and transfer; it is not a separate connection manager.

`--wingui` 会打开一个仅 Windows 可用的当前链路传输面板。它复用命令行里已经给出的 FlySsh 连接参数，并通过子 `flyssh.exe` 进程完成浏览与传输；它不是独立连接管理器。

```bash
flyssh --socks 127.0.0.1:1080 user1@hop1 user2@target --passwords 'p1,p2' --wingui
```

The GUI supports:

GUI 支持：

- local and remote directory browsing with back/forward/up/refresh / 本地与远端目录浏览，支持后退、前进、上级、刷新
- SCP and rsync upload/download buttons for the current selection / 对当前选择执行 SCP 或 rsync 上传/下载
- drag local files or folders onto the remote list to upload after choosing `rsync`, `SCP`, or `Cancel` / 将本地文件或文件夹拖到远端列表后，可选择 `rsync`、`SCP` 或取消
- delete selected local or remote items after confirmation / 确认后删除选中的本地或远端项目
- rename or move one selected local or remote item by editing its full path / 通过编辑完整路径重命名或移动单个选中的本地或远端项目
- remote size, modification time, and best-effort Unix `mode user:group`; unknown remote size/time is shown as `?` / 显示远端大小、修改时间，以及 best-effort 的 Unix `mode user:group`；未知的远端大小/时间显示为 `?`

Authentication, host-key, passphrase, and MFA prompts still happen in the terminal. Keep the launching console visible while the GUI is running.

认证、主机密钥、密钥口令和 MFA 提示仍在终端完成。GUI 运行期间请保留启动它的控制台窗口。

Transfer caveat:

传输注意事项：

- On permission-restricted targets, `rsync` upload may return exit code `23` while files are already transferred. This is a remote filesystem behavior, not a FlySsh protocol failure. / 在权限受限目标机上，`rsync` 上传可能返回 `23`，但文件内容已到达。这通常是目标文件系统行为，不是 FlySsh 协议失败。

### Windows rsync prerequisites / Windows rsync 前置条件

On Windows, `--rsync-upload` and `--rsync-download` require a working `rsync.exe`.  FlySsh searches for it in this order:

Windows 上使用 `--rsync-upload` / `--rsync-download` 需要可用的 `rsync.exe`。FlySsh 按以下顺序查找：

1. **Same directory as flyssh.exe** (recommended — simplest setup) / flyssh.exe 同目录（推荐，最简单）
2. **Current working directory** / 当前工作目录
3. **`%PATH%`** (covers Scoop `scoop install rsync`, Chocolatey, etc.) / 环境变量 PATH
4. **Well-known install paths**: MSYS2 (`C:\msys64\usr\bin`), Cygwin (`C:\cygwin64\bin`), cwRsync/ICW (`C:\Program Files\cwRsync\bin`, `C:\Program Files (x86)\ICW\bin`) / 已知安装路径

All MSYS2, Cygwin, and cwRsync builds of rsync are supported.  FlySsh automatically handles the Windows overlapped-I/O pipe limitation that affects Go processes forked by these rsync builds (see [Go #15388](https://github.com/golang/go/issues/15388)).

所有 MSYS2、Cygwin 和 cwRsync 版本的 rsync 均受支持。FlySsh 自动处理这些 rsync fork Go 进程时的 Windows overlapped I/O pipe 兼容问题。

**Quick setup / 快速配置：**

```
# Option A: Scoop (easiest, no admin)
scoop install rsync

# Option B: Copy from MSYS2 (portable)
# Copy rsync.exe + DLLs from C:\msys64\usr\bin\ to flyssh.exe directory
```

If rsync is not found, flyssh prints detailed installation instructions to stderr.

如果未找到 rsync，flyssh 会在 stderr 输出详细安装指引。

### Troubleshooting Logs / 排障日志

Use `-v` for detailed forwarding/reconnect traces:

使用 `-v` 获取详细转发/重连日志：

```bash
flyssh -v user:pass@host -L 127.0.0.1:8080:10.0.0.10:80
```

Log lines now include per-connection trace IDs for forwarding paths:

日志现在为转发路径增加了每连接 trace id：

- `L-000123` for local forward flow
- `R-000456` for remote forward flow
- `D-000789` for dynamic SOCKS flow

This makes it easier to correlate accept/connect/failure events for the same forwarded connection.

这可以把同一条转发连接的 accept/connect/failure 事件串起来看。

### Jump Hosts (ProxyJump) / 跳板机

```bash
flyssh -J jumpuser@jumphost user@target
flyssh -J jump1@host1,jump2@host2 user@target

# Through SOCKS5 / 通过 SOCKS5
flyssh --socks 127.0.0.1:1080 -J jumpuser@jumphost user@target
```

### Legacy Two-Hop / 传统双跳

Still supported for backward compatibility. 仍然支持向后兼容。

```bash
flyssh user1@hop1 --password pass1 --secondhost user2:pass2@hop2 -L 8080:remote:80
flyssh user1@hop1 --password pass1 --secondhost user2@hop2 --secondhostpass pass2 --secondhostkey /path/key
```

---

## How It Works / 工作原理

### Connection Flow / 连接流程

```
[Local] → (SOCKS5 proxy) → [Hop1] → [Hop2] → ... → [HopN] (shell + forwarding)
```

### Forwarding Strategy / 转发策略

For each hop, FlySsh tries (in order): 对每一跳，FlySsh 按顺序尝试：

1. **direct-tcpip** — standard SSH channel forwarding (fastest) / 标准 SSH 通道转发（最快）
2. **Mux relay** — embedded binary, 1 SSH session for unlimited connections / 内置中继，1 个会话无限连接
3. **Exec fallback** — nc / socat / perl / python / bash relay (per-connection) / 逐连接中继

The mux relay is uploaded automatically when needed (hash-based caching — only uploads once per binary version). It runs in multiplexed mode: a single SSH exec session handles all forwarded connections via binary framing.

复用中继在需要时自动上传（基于哈希缓存——每个版本只上传一次）。它以复用模式运行：单个 SSH exec 会话通过二进制帧处理所有转发连接。

### Supported Relay Platforms / 中继支持的平台

| Platform / 平台 | Embedded / 内嵌 |
|---|---|
| Linux amd64 | ✅ |
| Linux arm64 | ✅ |
| macOS Intel (amd64) | ✅ |
| macOS Apple Silicon (arm64) | ✅ |
| Windows | ❌ (use Bitvise forwarding / 使用 Bitvise 转发) |

---

## Authentication / 认证

```bash
# Inline password / 内联密码
flyssh user:password@hostname

# --password flag
flyssh user@hostname --password mypass

# From environment variable / 从环境变量
flyssh user@hostname --password-env MY_SSH_PASS

# From file (more secure) / 从文件（更安全）
flyssh user@hostname --password-file /path/to/passfile

# Public key / 公钥
flyssh -i ~/.ssh/id_ed25519 user@hostname

# SSH Agent / SSH 代理
flyssh -A user@hostname

# Interactive prompt (default) / 交互式提示（默认）
flyssh user@hostname
```

### Host Key Behavior / 主机密钥行为

- **Default**: Auto-accept new fingerprints, save to `~/.ssh/known_hosts` / 默认：自动接受新指纹并保存
- **Changed key**: Warning + block (possible MITM) / 密钥变更：警告 + 阻止（可能的中间人攻击）
- `-o StrictHostKeyChecking=ask` — classic OpenSSH yes/no prompt / 经典 OpenSSH 确认提示
- `-o StrictHostKeyChecking=no` — accept everything / 接受所有

---

## SSH Config Support / SSH 配置支持

FlySsh reads `~/.ssh/config` automatically:

FlySsh 自动读取 `~/.ssh/config`：

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

```bash
flyssh --socks 127.0.0.1:1080 myserver
```

---

## Testing / 测试

Run full local test suite:

运行本地全量测试：

```bash
go test ./...
```

Race detector (recommended before release):

竞态检测（发布前建议跑）：

```bash
go test -race ./...
```

Stability repeat run:

稳定性重复运行：

```bash
go test ./... -count=5
```

CI now runs:

CI 现在会执行：

- Normal test suite / 常规测试
- Race detector / 竞态检测
- Repeated run for flake detection / 重复运行检测偶发失败

---

## All Options / 所有参数

```
flyssh [options] [user[:pass]@]host[:port] [user2[:pass2]@host2[:port2] ...] [command]

SSH Options (OpenSSH compatible):
  -4              Force IPv4 / 强制 IPv4
  -6              Force IPv6 / 强制 IPv6
  -A              Enable agent forwarding / 启用代理转发
  -a              Disable agent forwarding / 禁用代理转发
  -b bind_addr    Bind address / 绑定地址
  -C              Enable compression / 启用压缩
  -c cipher       Cipher specification / 加密算法
  -D [bind:]port  Dynamic forward (SOCKS5) / 动态转发
  -E log_file     Log file / 日志文件
  -e char         Escape character (default: ~) / 转义字符
  -F config       SSH config file / SSH 配置文件
  -f              Background after auth / 认证后后台运行
  -g              Allow remote connects to forwarded ports / 允许远程连接转发端口
  -i identity     Identity file / 密钥文件
  -J destination  ProxyJump / 跳板机
  -L spec         Local port forwarding / 本地端口转发
  -l login_name   Login name / 登录名
  -m mac_spec     MAC specification / MAC 算法
  -N              No command (forwarding only) / 仅转发
  -o key=value    SSH option / SSH 选项
  -p port         Port (default: 22) / 端口
  -q              Quiet mode / 静默模式
  -R spec         Remote port forwarding / 远程端口转发
  -s              Subsystem / 子系统
  -T              Disable PTY / 禁用伪终端
  -t              Force PTY / 强制伪终端
  -V              Show version / 显示版本
  -v              Verbose mode / 详细模式
  -W host:port    Stdio forwarding / 标准流转发
  -X              X11 forwarding / X11 转发
  -Y              Trusted X11 forwarding / 受信 X11 转发

FlySsh Extensions:
  --socks host:port       SOCKS5 proxy / SOCKS5 代理
  --socks-user user       SOCKS5 username / SOCKS5 用户名
  --socks-pass pass       SOCKS5 password / SOCKS5 密码
  --password pass         Password for first host / 首跳密码
  --password-env VAR      Read password from env / 从环境变量读密码
  --password-file PATH    Read password from file / 从文件读密码
  --passwords "p1,,p3"    Per-hop passwords / 逐跳密码
  --keys "k1,,k3"         Per-hop identity files / 逐跳密钥
  --rsync-upload '...'    Managed rsync upload / 托管 rsync 上传
  --rsync-download '...'  Managed rsync download / 托管 rsync 下载
  --scp-upload '...'      Built-in SCP upload / 内置 SCP 上传
  --scp-download '...'    Built-in SCP download / 内置 SCP 下载
  --wingui                Windows companion transfer GUI / Windows 图形传输面板
  --no-reconnect          Disable auto-reconnect / 禁用自动重连
  --reconnect-delay N     Reconnect delay seconds / 重连延迟秒数
  --ssh-gateway spec      Local SSH gateway 'user:pass@bind:port' / 本地 SSH 网关
  --mosh                  Built-in mosh-over-FlySSH terminal / 内置 mosh-over-FlySSH 终端
  --mosh-session NAME     Reattach/create named mosh session / 接回或创建固定 mosh 会话

  -ltcp://spec[,spec...]  Easy local forward / 简易本地转发
  -rtcp://spec[,spec...]  Easy remote forward / 简易远程转发
  -dynamicproxy://port    Easy dynamic forward / 简易动态转发

Legacy Two-Hop:
  --secondhost user:pass@host:port
  --secondhostkey PATH
  --secondhostpass PASS
```

---

## Security Notes / 安全说明

- `--password` on command line may appear in shell history. Use `--password-env` or `--password-file` for better security.
- `--ssh-gateway` password on command line may appear in shell history. FlySsh scrubs `argv` immediately after start, but the shell records history before the process launches.
- `--mosh-session` names are not passwords, but they identify reusable remote sessions. Choose non-sensitive names and avoid sharing them on multi-user systems.
- FlySsh scrubs `argv` at startup to hide passwords from `/proc/self/cmdline` and process listings.
- Host keys are auto-accepted on first connection and saved to `~/.ssh/known_hosts`. Changed keys are blocked.

- 命令行中的 `--password` 可能出现在 shell 历史记录中。建议使用 `--password-env` 或 `--password-file`。
- `--ssh-gateway` 的密码同样可能出现在 shell 历史记录中。FlySsh 启动后立即清除 `argv`，但 shell 在进程启动前已记录历史。
- `--mosh-session` 名称不是密码，但它会标识可复用的远端会话。建议使用不敏感名称，且不要在多用户系统上随意共享。
- FlySsh 启动时清除 `argv` 以隐藏密码，防止在进程列表中泄露。
- 首次连接自动接受主机密钥并保存到 `~/.ssh/known_hosts`，密钥变更时阻止连接。

---

## License / 许可证

[MIT](./LICENSE)
