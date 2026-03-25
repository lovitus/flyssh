# Changelog / 更新日志

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
