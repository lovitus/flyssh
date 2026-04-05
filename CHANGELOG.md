# Changelog / 更新日志

## v1.0.15 (2026-04-06)

### CI / Release

- **Retag release on the corrected workflow commit** — `v1.0.14` was accidentally created from an older commit before the workflow fix landed, so `v1.0.15` republishes the same intended release content from the commit that includes both the deterministic release-note extraction and the YAML indentation fix / 在修正后的 workflow 提交上重新打版：`v1.0.14` 误打到了 workflow 修复落地前的旧提交，因此 `v1.0.15` 会从包含“稳定 release note 提取”和 “YAML 缩进修复”两项变更的正确提交重新发布相同的预期内容

### Verification / 验证

- Confirmed current `HEAD` is [d2c1a5b](/Users/fanli/flyssh/.git/refs/heads/main) with the workflow fix
- Confirmed remote `v1.0.14` tag points to an older commit and therefore cannot produce the intended release / 已确认远端 `v1.0.14` 标签指向旧提交，因此无法生成预期 release

---

## v1.0.14 (2026-04-06)

### CI / Release

- **Fix release workflow YAML for Python-based changelog slicing** — indent the embedded Python block correctly under `run: |` so GitHub Actions parses the workflow again and the deterministic release note extraction added in `v1.0.13` can actually execute / 修复基于 Python 的 changelog 切段逻辑在 release workflow 中的 YAML 结构：把嵌入的 Python 代码正确缩进到 `run: |` 下，让 GitHub Actions 能重新解析 workflow，并真正执行 `v1.0.13` 引入的稳定 release note 提取逻辑

### Verification / 验证

- Local inspection of [release.yml](/Users/fanli/flyssh/.github/workflows/release.yml) after indentation fix
- Prior `v1.0.12` run already confirmed tests and artifact builds passed
- Prior `v1.0.13` runs failed before job start, confirming the remaining issue was workflow parsing rather than build/test behavior / 之前的 `v1.0.13` 运行在 job 启动前即失败，说明剩余问题是 workflow 解析而不是构建/测试行为

---

## v1.0.13 (2026-04-06)

### CI / Release

- **Make release note extraction deterministic on GitHub runners** — replace the shell `awk` changelog slicer with Python UTF-8 parsing so release jobs no longer fail after successful builds and tests just because the runner failed to detect the current `## v...` section / 让 GitHub runner 上的 release note 提取更稳定：用 Python UTF-8 解析替换 shell `awk` 的 changelog 切段逻辑，避免构建和测试成功后因 runner 未正确识别当前 `## v...` 段落而导致发布失败

### Verification / 验证

- Local reproduction of release note extraction with `v1.0.13` changelog section
- Prior `v1.0.12` release run already confirmed `Test` and artifact build steps passed before failing only at release note extraction / 之前的 `v1.0.12` release run 已确认测试和产物构建都通过，失败点仅在 release note 提取

---

## v1.0.12 (2026-04-06)

### Bug Fixes / 修复

- **Remove OS socket timing from prompt broker cleanup tests** — the abandoned-prompt cleanup test now uses an in-memory single-connection listener instead of real TCP/Unix sockets, eliminating GitHub runner-specific timing differences that could still leave release CI hanging / 移除 prompt broker cleanup 测试对 OS socket 时序的依赖：abandoned-prompt cleanup 测试现在改用内存内单连接 listener，而不再依赖真实 TCP/Unix socket，消除了 GitHub runner 上可能继续导致 release CI 卡住的平台时序差异

### Verification / 验证

- `go test ./pkg/auth -run TestPromptBrokerCleanupDoesNotWaitForAbandonedPrompt -count=100`
- `go test -race ./pkg/auth -run TestPromptBrokerCleanupDoesNotWaitForAbandonedPrompt -count=50`
- `go test ./...`

---

## v1.0.11 (2026-04-06)

### Bug Fixes / 修复

- **Stabilize prompt broker cleanup test in CI** — the abandoned-prompt cleanup test now waits for the broker worker to actually start before simulating disconnect, and its deferred worker shutdown wait is bounded so GitHub Actions no longer burns the full package timeout on a missed synchronization edge / 稳定 CI 中的 prompt broker cleanup 测试：abandoned-prompt 清理测试现在会先等待 broker worker 真正启动再模拟断连，并为 defer 中的 worker 退出等待增加超时，避免 GitHub Actions 在同步边界没对齐时耗尽整个包级超时
- **Make release test logs package/test visible** — the release workflow now runs `go test -v ./...` so if CI ever stalls or fails again, the last running package and test case are visible directly in the Actions log / 提升 release 测试日志可诊断性：release workflow 现在改为执行 `go test -v ./...`，后续若 CI 再次卡住或失败，可以直接从 Actions 日志看到最后执行到的包和测试用例

### Verification / 验证

- `go test ./pkg/auth -run TestPromptBrokerCleanupDoesNotWaitForAbandonedPrompt -count=20`
- `go test ./pkg/auth`
- `go test -race ./pkg/auth`
- `go test ./...`

---

## v1.0.10 (2026-04-06)

### Bug Fixes / 修复

- **Restrict SCP status output to interactive terminals** — built-in SCP progress messages now stay silent in non-TTY contexts and still honor `-q`, avoiding stderr regressions in CI jobs, scripts, and automation that expect clean success output / 收紧 SCP 状态输出到交互式终端：内置 SCP 进度信息现在仅在 TTY 场景默认显示，并继续遵守 `-q`，避免在 CI、脚本和依赖干净 stderr 的自动化场景中引入行为回归
- **Escape SCP status filenames before printing** — transferred paths shown in progress output are now safely quoted so remote-controlled filenames cannot inject fake log lines or terminal control sequences / 转义 SCP 状态中的文件名：进度输出里的传输路径现在会安全引用，避免远端可控文件名伪造日志行或注入终端控制序列
- **Gate SCP completion messaging on real success** — completion status is emitted only when the transfer exits with code `0` and no error, preventing false success messages on non-zero remote exits / 按真实成功条件输出 SCP 完成信息：仅当传输退出码为 `0` 且无错误时才显示完成状态，避免远端非零退出时误报成功

### Verification / 验证

- `go test ./pkg/transfer`
- `go test -race ./pkg/transfer`
- `go test ./...`
- Live SCP validation on `node4`: quiet mode stays silent, interactive mode still shows start/file/complete status / 基于 `node4` 的 SCP 实机验证：`-q` 模式保持静默，交互模式仍显示开始/文件/完成状态

---

## v1.0.9 (2026-04-06)

### Bug Fixes / 修复

- **Fix changed-host-key confirmation for managed rsync without double-auth side effects** — replace the failed rsync preflight approach with a single-connection prompt broker so `--rsync-upload` / `--rsync-download` can accept `confirm fingerprint changed` and other interactive auth prompts without opening an extra SSH login / 修复托管 rsync 的 changed-host-key 确认且避免双重认证副作用：移除有问题的 rsync 预连接方案，改为单连接 prompt broker，使 `--rsync-upload` / `--rsync-download` 在不额外建立 SSH 登录的前提下正确处理 `confirm fingerprint changed` 与其他交互认证提示
- **Make prompt broker failure non-fatal for non-interactive rsync paths** — broker startup now prefers local Unix sockets where available and degrades gracefully to the existing tty path if no listener can be created, avoiding a new hard dependency on loopback TCP listeners / 降低 prompt broker 对非交互 rsync 路径的侵入性：broker 优先使用本地 Unix socket，若监听建立失败则自动回退到原有 tty 输入路径，不再把 loopback TCP 监听能力变成新的硬前置条件
- **Avoid broker shutdown hangs on abandoned prompts** — pending prompt requests now observe peer disconnects and broker shutdown so cancelled transfers and failed auth flows do not block cleanup waiting for an orphaned tty read / 修复 broker 在孤儿 prompt 上的退出挂死：待处理提示现在会感知对端断开和 broker 关闭，取消传输或认证失败时不会再因遗留 tty 读取而卡住清理流程

### Verification / 验证

- Automated tests: `go test ./...` and `go test -race ./...` / 自动化测试：`go test ./...` 与 `go test -race ./...`
- Live transfer checks with provided lab nodes: single-hop and multi-hop `scp` / `rsync`, wrong-password auth failure, and real changed-host-key confirmation across single-hop, first-hop, and second-hop routes / 实机验证：基于提供的测试节点完成单跳与多跳 `scp` / `rsync`、错误密码认证失败，以及真实 changed-host-key 场景下的单跳、首跳和次跳确认流程验证

---

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
