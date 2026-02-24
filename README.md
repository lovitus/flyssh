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
- **Auto-reconnect** — reconnects on connection loss when credentials are non-interactive / 非交互凭据下自动重连
- **Idle timeout** — inactive forwarded connections auto-close after 5 minutes / 空闲连接 5 分钟自动关闭
- **Single binary** — no dependencies, cross-platform (Windows/Linux/macOS, amd64/arm64) / 单文件无依赖，跨平台

---

## Installation / 安装

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
```

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
| Host key auto-accept / 自动接受指纹 | default | Auto-accept new fingerprints / 自动接受新指纹 |

---

## Usage / 用法

### Basic Connection / 基本连接

```bash
flyssh user@hostname
flyssh user:password@hostname
flyssh -p 2222 user@hostname
flyssh user@hostname "ls -la"
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
  --no-reconnect          Disable auto-reconnect / 禁用自动重连
  --reconnect-delay N     Reconnect delay seconds / 重连延迟秒数

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
- FlySsh scrubs `argv` at startup to hide passwords from `/proc/self/cmdline` and process listings.
- Host keys are auto-accepted on first connection and saved to `~/.ssh/known_hosts`. Changed keys are blocked.

- 命令行中的 `--password` 可能出现在 shell 历史记录中。建议使用 `--password-env` 或 `--password-file`。
- FlySsh 启动时清除 `argv` 以隐藏密码，防止在进程列表中泄露。
- 首次连接自动接受主机密钥并保存到 `~/.ssh/known_hosts`，密钥变更时阻止连接。

---

## License / 许可证

MIT
