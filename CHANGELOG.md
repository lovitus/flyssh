# Changelog / 更新日志

## v1.0.8 (2026-04-05)

### Bug Fixes / 修复

- **Fix host-key confirmation during managed transfers** — interactive host-key confirmation, password prompts, passphrase prompts, and keyboard-interactive responses now read from the controlling terminal instead of protocol stdin, so `--rsync-upload` / `--rsync-download` no longer hang after typing `confirm fingerprint changed` / 修复托管传输期间的主机密钥确认卡住问题：交互式主机密钥确认、密码输入、密钥口令输入和 keyboard-interactive 响应现在统一从控制终端读取，不再与协议 stdin 冲突，因此 `--rsync-upload` / `--rsync-download` 输入 `confirm fingerprint changed` 后不会再无响应

### Verification / 验证

- `go test ./pkg/auth`
- `go test ./...`
- `go test -race ./pkg/auth`
- `go test -race ./...`

---

## v1.0.7 (2026-04-05)

### Bug Fixes / 修复

- **Fix SCP stderr data race under `-race`** — replace unsynchronized stderr capture buffer in SCP transfer sessions with a lock-protected buffer, removing concurrent read/write races detected in CI race runs / 修复 `-race` 下 SCP stderr 数据竞争：将 SCP 会话中的 stderr 缓冲改为加锁实现，消除 CI 竞态检测发现的并发读写问题

### Verification / 验证

- `go test ./...`
- `go test -race ./...`

---

## v1.0.6 (2026-04-05)

### Features / 功能

- **Built-in transfer modes added** — new `--scp-upload`, `--scp-download`, `--rsync-upload`, and `--rsync-download` modes run file transfers over existing FlySsh routes (single-hop, multi-hop, and SOCKS-supported paths) / 新增内置传输模式：`--scp-upload`、`--scp-download`、`--rsync-upload`、`--rsync-download`，可在现有 FlySsh 路由下执行文件传输（支持单跳、多跳与 SOCKS 路径）
- **Managed rsync transport path** — FlySsh now provides an internal rsync transport bridge so outer auth/routing remains under FlySsh control while still using the local system `rsync` binary / 新增托管 rsync 传输路径：通过 FlySsh 内部桥接保持外层认证与路由控制，同时复用本地系统 `rsync`

### Bug Fixes / 修复

- **Fix first-hop password assignment for `--passwords`** — the first CSV entry now correctly maps to host1 in both single-hop and multi-hop flows / 修复 `--passwords` 首跳密码映射：CSV 第一项现在正确作用于首跳（单跳与多跳）
- **Avoid option mutation during connection planning** — reconnect attempts no longer duplicate identity material due to in-place option mutations / 修复连接规划阶段参数被原地修改的问题，避免重连中密钥参数重复累积
- **Harden host-key callback for nil remote address** — multi-hop host-key checks no longer risk panic when callback receives a nil remote endpoint / 加固主机密钥回调：多跳场景下 remote 地址为 nil 时不再有 panic 风险

### Docs / 文档

- **Transfer documentation completed** — README now includes transfer mode rules, constraints, end-to-end examples, and environment-specific rsync caveats / 完成传输文档：README 现已包含传输模式规则、限制、端到端示例和 rsync 环境告警说明
- **Validation report linked and aligned** — live validation outcomes and known environment-specific behavior are documented and cross-referenced / 补全验证报告并与实现对齐：记录实机验证结果与环境侧已知行为

### Verification / 验证

- Automated tests: `go test ./...` / 自动化测试：`go test ./...`
- Live checks: single-hop and multi-hop SCP/rsync transfers, plus wrong-password auth failure validation / 实机验证：单跳与多跳 SCP/rsync 传输，以及错误密码认证失败场景

---

## v1.0.5 (2026-03-25)

### Bug Fixes / 修复

- **Fix interactive input freeze after repeated reconnects** — interactive sessions now use a process-level single stdin reader with active-session routing, preventing stale readers from previous sessions from swallowing keyboard input after long-running reconnect loops / 修复重连多轮后的交互输入冻结：交互模式改为进程级单一 stdin 读取并路由到当前会话，避免旧会话残留读取器吞掉按键
- **Reduce key-loss window on reconnect** — stdin routing is bound before `session.Shell()` starts so the first keystrokes after reconnect are not dropped during shell startup / 缩小重连后首键丢失窗口：在 `session.Shell()` 前绑定 stdin 路由，降低 shell 启动瞬间按键丢失概率

### CI / Release

- **GitHub Actions release pipeline added** — pushing a `v*` tag now runs tests, cross-builds all supported targets, packages artifacts, generates checksums, and publishes assets to GitHub Releases / 新增 GitHub Actions 发布流水线：推送 `v*` 标签即可自动测试、全平台构建、打包、生成校验并上传到 Releases

### Verification / 验证

- Build validation: `go test ./...` and `go build ./...` passed on release branch / 发布分支已通过 `go test ./...` 与 `go build ./...`

---

## v1.0.4 (2026-03-25)

### Bug Fixes / 修复

- **Fix interactive input freeze after reconnect loops** — use a single process-level stdin router for interactive shell sessions, so repeated reconnects no longer leave stale input readers that can swallow keystrokes / 修复交互重连多轮后输入失效：改为进程级单一 stdin 路由，避免旧会话残留读取导致按键被吞

---

## v1.0.3 (2026-03-04)

### Bug Fixes / 修复

- **Interactive auto-reconnect no longer waits for Enter** — on connection loss, reconnect now starts immediately without requiring keyboard input; channels recover automatically / 交互模式断线后无需再按回车触发重连，自动重连会立即启动并恢复通道
- **Stop terminal resize watcher on session end** — avoids goroutine leaks across repeated reconnects / 会话结束时停止终端尺寸监听，避免反复重连导致协程泄漏

---

## v1.0.1 (2026-02-24)

### Bug Fixes / 修复

- **Auto-reconnect now works correctly** — connection loss (SOCKS proxy restart, network drop) triggers automatic retry instead of silent exit / 自动重连修复：连接丢失后正确触发重连，不再静默退出
- **Close listeners when SSH dies** — local/dynamic forward listeners now close immediately when the SSH connection drops, preventing log spam and stale ports / SSH 断开时立即关闭监听端口，避免日志洪水和端口残留
- **Rate-limit forward error logs** — duplicate "connect failed" messages are suppressed (max 1 per 2 seconds per forward) / 转发错误日志去重，每 2 秒最多打印 1 条
- **First hop supports `user:pass@host:port`** — inline credentials now work for the first positional argument, not just extra hops / 首跳支持内联密码格式
- **Host key auto-accept by default** — new fingerprints are auto-accepted and saved (like `StrictHostKeyChecking=accept-new`), no more yes/no prompt / 默认自动接受新主机指纹
- **`-ltcp://` and `-rtcp://` support comma-separated pairs** — e.g. `-ltcp://:5001/:5000,:2222/192.168.1.1:22` / 支持逗号分隔多组转发

---

## v1.0.0 (2026-02-24)

### Features / 功能

- **SOCKS5 proxy built-in** — connect through SOCKS5 without external tools / 内置 SOCKS5 代理
- **Unlimited multi-hop SSH chaining** — chain through N machines with positional args / 无限多跳链接
- **Multiplexed relay** — embedded binary tunnels all forwards over 1 SSH session, bypasses `MaxSessions` / 复用中继绕过 MaxSessions
- **Hash-based relay caching** — relay binary uploaded once per version, skips re-upload on reconnect / 基于哈希缓存中继
- **Multi-platform relay** — embedded for linux/darwin (amd64/arm64) / 多平台中继支持
- **Per-hop credentials** — `--keys` and `--passwords` for comma-separated per-hop auth / 逐跳凭据
- **GOST-style easy forwarding** — `-ltcp://`, `-rtcp://`, `-dynamicproxy://` / GOST 风格简易转发
- **Auto-reconnect** — automatic retry on connection loss with non-interactive credentials / 自动重连
- **Idle timeout** — inactive forwarded connections auto-close after 5 minutes / 空闲连接超时
- **Full OpenSSH compatibility** — `-L`, `-R`, `-D`, `-J`, `-W`, `-i`, `-A`, `-F`, SSH config, etc.
- **Cross-platform** — Windows, Linux, macOS (amd64/arm64) / 跨平台支持
- **Argv scrubbing** — passwords hidden from process listings / 进程列表密码隐藏
