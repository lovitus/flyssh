# Changelog / 更新日志

## v2.0.11 (2026-08-10)

### Features / 新功能

- **Open external SSH clients from the Windows transfer GUI** — The companion GUI now provides PuTTY, Xshell, and SecureCRT buttons. Each client connects through a loopback-only, ephemeral FlySSH SSH gateway that reuses the GUI's existing host, proxy, authentication, and multi-hop arguments / Windows 传输 GUI 现在可直接打开 PuTTY、Xshell 和 SecureCRT。外部客户端通过仅监听回环地址的临时 FlySSH SSH gateway 连接，并复用 GUI 已有的目标、代理、认证和多跳参数。
- **Discover or select shell client executables** — FlySSH searches beside its own executable, Windows App Paths, `PATH`, and standard installation directories. If a client is not found, its button opens a file picker; the selected executable is retained only for the current GUI session / FlySSH 会在自身目录、Windows App Paths、`PATH` 和常见安装目录中查找终端客户端；未找到时按钮会打开文件选择框，所选路径只在当前 GUI 会话中保留。

### Security and lifecycle / 安全与生命周期

- The temporary gateway uses random per-GUI credentials, reports its generated host-key fingerprints for client pinning, and is terminated when the FlySSH GUI closes. Sensitive internal gateway arguments are redacted from logs and excluded from internal rsync payloads / 临时 gateway 使用每次 GUI 会话随机生成的凭据，并返回 host key 指纹供客户端校验；关闭 FlySSH GUI 时会终止 gateway。内部 gateway 敏感参数会从日志中脱敏，也不会进入 rsync internal payload。

### Verification / 验证

- `go test ./...`
- `go vet ./...`
- `go test -race ./pkg/gateway ./pkg/cli ./pkg/transfer ./pkg/wingui`
- Windows amd64 cross-build and native Wingui tests
- Windows UI automation for missing-client selection and session-only executable reuse

---

## v2.0.10 (2026-07-22)

### Features / 新功能

- **Add configurable forwarding relay policy** — Port forwarding now supports global `--relay=auto|disable|prefer` selection and per-entry `?relay=...` overrides for easy-forward syntax. Existing local and dynamic forwarding keep their default direct-then-relay order / 新增可配置的转发中继策略：端口转发现在支持全局 `--relay=auto|disable|prefer`，easy-forward 语法也支持单条 `?relay=...` 覆盖；本地和动态转发继续保持默认的 direct-then-relay 顺序。
- **Add mux relay fallback for remote forwarding** — When sshd explicitly denies `tcpip-forward`, the default `auto` policy can create the remote listener through the embedded mux relay. `--relay=disable` retains strict sshd-only behavior / 为远程转发增加 mux relay 兜底：当 sshd 明确拒绝 `tcpip-forward` 时，默认 `auto` 策略可通过内嵌 mux relay 创建远端监听；`--relay=disable` 可保持严格的仅 sshd 行为。

### Fixes / 修复

- **Preserve gateway command output after stdin EOF** — The SSH gateway now half-closes only the upstream write side when a downstream client finishes stdin, allowing stdout, stderr, and exit status to drain normally / 修复 gateway 在 downstream stdin EOF 后过早关闭整个上游 channel、导致命令输出丢失的问题：现在只半关闭上游写端，stdout、stderr 和退出状态可正常返回。
- **Report forwarding idle-timeout closures** — When the existing five-minute forwarding idle watchdog closes a connection, FlySSH now logs the exact reason and timeout to distinguish local cleanup from upstream network disconnects / 转发连接被现有五分钟 idle watchdog 关闭时，现在会明确记录原因和超时，便于区分本地清理与上游网络断开。

### Verification / 验证

- `go test ./...`
- `go test -race ./...`
- `go test ./... -count=5`
- Windows, Linux, and macOS cross-builds

---

## v2.0.9 (2026-06-12)

### Fixes / 修复

- **Recover from remote forward registration failures in `-N` mode** — Forwarding-only sessions now propagate local, remote, and dynamic forward errors back to the main connection loop instead of only logging them. This lets `-rtcp` / remote forwarding fail fast and enter the existing reconnect path when the remote listen port is still occupied by a stale server-side SSH process after an abnormal network break / 修复 `-N` forwarding-only 模式下远端转发注册失败后只写日志、不触发重连的问题：现在 local、remote、dynamic forward 的错误会返回到主连接循环。遇到异常断网后远端旧 `sshd` 仍占用 `-rtcp` 端口时，FlySSH 会明确失败并进入已有重连流程。
- **Watch all SSH clients during forwarding-only sessions** — `-N` mode now exits when any hop in the active SSH chain closes, not only when the first client reports closure / forwarding-only 会话现在会监听整条 SSH 链中的任意 client 关闭，而不是只等待第一个 client。

### Verification / 验证

- `git diff --check`
- `go test ./...`
- `go test -race ./...`
- `GOOS=windows GOARCH=amd64 go build .`

---

## v2.0.8 (2026-06-07)

### Fixes / 修复

- **Fix long-running `--mosh` client memory growth** — FlySSH now depends on `github.com/lovitus/mosh-go v0.5.2-flyssh.10`, which compacts acknowledged client input actions and reuses cached compressed pending diffs to avoid repeated zlib/flate allocations during long sessions / 修复长时间 `--mosh` 会话中的客户端内存增长问题：FlySSH 现在依赖 `github.com/lovitus/mosh-go v0.5.2-flyssh.10`，该版本会裁剪已确认的客户端输入 action，并复用 pending diff 的压缩结果，避免长会话中反复进行 zlib/flate 分配。

### Verification / 验证

- `go test ./...`
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/flyssh-mosh-oom-fix.exe .`

---

## v2.0.7 (2026-06-04)

### Fixes / 修复

- **Enable default SSH keepalive across long-running modes** — FlySSH now sends SSH keepalive traffic by default every 30 seconds across normal sessions, SCP, rsync, and `--ssh-gateway`, reducing disconnects caused by proxies, firewalls, or jump hosts around the 140 second idle/one-way traffic mark / 在长时间运行模式中默认启用 SSH 保活：FlySSH 现在默认每 30 秒在普通会话、SCP、rsync 和 `--ssh-gateway` 链路上发送 SSH keepalive，减少代理、防火墙或跳板机在约 140 秒空闲/单向流量后断开连接的问题。
- **Track explicit `ServerAliveInterval` configuration** — `ServerAliveInterval` values from SSH config or `-o` are now tracked even when set to `0`; FlySSH still keeps the practical 30 second default enabled and prints a warning when an explicit zero is requested / 跟踪显式配置的 `ServerAliveInterval`：来自 SSH config 或 `-o` 的值即使为 `0` 也会被识别；FlySSH 仍保留实用的 30 秒默认保活，并在用户显式设置 `0` 时输出提示。
- **Use non-blocking keepalive requests** — keepalive requests no longer wait for a server reply, focusing on keeping the route active without treating servers that ignore OpenSSH keepalive global requests as failed / 使用不等待响应的 keepalive 请求：保活请求不再等待服务端回复，重点保持链路活跃，避免把忽略 OpenSSH keepalive global request 的服务端误判为失败。

### Verification / 验证

- `git diff --check`
- `go test ./...`
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/flyssh-keepalive-check.exe .`

---

## v2.0.6 (2026-06-03)

### Fixes / 修复

- **Keep internal rsync transport connections alive during large uploads** — the `--internal-rsync-transport` path now sends SSH keepalives across the active chain while rsync is running, using configured `ServerAliveInterval` when present and a conservative 30 second default otherwise. This targets large rsync uploads that can be reset by proxies, firewalls, or jump hosts after a few minutes of one-way transfer traffic / 修复大文件 rsync 上传期间 internal transport 连接可能被中间代理、防火墙或跳板重置的问题：`--internal-rsync-transport` 现在会在 rsync 运行期间对整条 SSH 链路发送 keepalive；若已配置 `ServerAliveInterval` 则使用该配置，否则使用保守的 30 秒默认值。

### Verification / 验证

- `git diff --check`
- `go test ./pkg/transfer`
- `go test ./...`

---

## v2.0.5 (2026-05-29)

### Fixes / 修复

- **Harden Windows rsync upload fallback** — after the normal rsync probe and `/cygdrive` / `/d` retries fail with the known Windows `change_dir "..."/...` quoting symptom, FlySSH now retries upload sources from their Windows parent directory and can use `--from0 --files-from=-` for filenames or directories containing spaces and non-ASCII characters. Multi-directory uploads are grouped safely when no delete or relative flags are present / 加强 Windows rsync 上传兜底：当常规 probe 以及 `/cygdrive` / `/d` 重试后仍命中特定 Windows `change_dir "..."/...` 引号异常时，FlySSH 会从 Windows 源父目录重试，并可用 `--from0 --files-from=-` 处理包含空格和非 ASCII 字符的文件名或目录名；不同目录上传在无 delete/relative flags 时按父目录安全分组重试。
- **Remove unsafe native Windows rsync retry** — FlySSH no longer retries `D:\...` native paths because rsync can interpret drive-letter operands as remote host syntax / 移除不安全的原生 Windows 路径重试：`D:\...` 可能被 rsync 解析成远端 host 语法，因此不再作为兜底路径。

### Verification / 验证

- `go test ./pkg/transfer`
- `go test ./...`

---

## v2.0.4 (2026-05-28)

### Fixes / 修复

- **Add a targeted Windows rsync path retry** — when a Windows rsync upload/download first fails with the known `change_dir "..."/cygdrive/...` or `change_dir "..."/d/...` quoting/path-style symptom, FlySSH now retries once through the remaining Windows local path forms (`/cygdrive/...`, `/d/...`, native `D:\...`) while leaving the normal rsync probe/fallback path unchanged / 新增 Windows rsync 路径兜底重试：当首次 rsync 传输命中特定 `change_dir "..."/cygdrive/...` 或 `change_dir "..."/d/...` 引号/路径风格异常时，FlySSH 会在不改变原有 probe/fallback 正常路径的前提下，补试其它 Windows 本地路径形态（`/cygdrive/...`、`/d/...`、原生 `D:\...`）。

### Verification / 验证

- `go test ./pkg/transfer`
- `go test ./...`

---

## v2.0.3 (2026-05-25)

### Packaging / 打包

- **Add APT and RPM repository publishing** — stable releases now build Debian/Ubuntu and RPM packages for mainstream 64-bit Linux targets, publish signed repository metadata to GitHub Pages, and document `apt`, `dnf`, and `yum` install/update commands / 新增 APT 与 RPM 官方源发布：正式版本现在会为主流 64 位 Linux 生成 Debian/Ubuntu 与 RPM 包，将签名后的仓库 metadata 发布到 GitHub Pages，并在 README 中补充 `apt`、`dnf`、`yum` 安装和更新命令。
- **Protect package repository updates from rollback** — the Linux package repository workflow keeps an explicit `latest.json` state file so manually rebuilding an older tag can add historical packages without downgrading latest metadata / 防止包源回滚：Linux 包源发布流程维护明确的 `latest.json` 状态文件，手动重跑旧 tag 时可追加历史包，但不会把 latest metadata 降级。
- **Separate APT and RPM signing formats** — APT publishes a binary keyring while RPM publishes an ASCII armored public key; RPM v1 signs repository metadata but not individual RPM packages / 区分 APT 与 RPM 签名格式：APT 发布 binary keyring，RPM 发布 ASCII armored public key；RPM v1 签名仓库 metadata，暂不签名单个 RPM 包。

### Verification / 验证

- `go test ./...`
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/flyssh-packaging-check.exe .`
- `bash -n .github/scripts/build_linux_packages.sh .github/scripts/update_linux_repos.sh`
- `ruby -e 'require "yaml"; YAML.load_file(".github/workflows/release.yml")'`
- `nfpm` package smoke test for amd64/arm64 deb and x86_64/aarch64 rpm
- APT/RPM repository update script smoke test

---

## v2.0.2 (2026-05-25)

### Packaging / 打包

- **Add repository-local Homebrew and Scoop install support** — the repository now includes `Formula/flyssh.rb` and `bucket/flyssh.json`, so users can install and update FlySSH through Homebrew or Scoop without a separate package repository / 新增当前仓库内置 Homebrew 与 Scoop 安装支持：用户无需额外包仓库即可通过 Homebrew 或 Scoop 安装和更新 FlySSH。
- **Automatically update package manifests after releases** — the release workflow now rewrites the Homebrew formula and Scoop manifest from the freshly generated `checksums.txt` after publishing release assets, then commits the updated manifests back to `main` / 发布流程会在上传 release assets 后，根据新生成的 `checksums.txt` 自动更新 Homebrew formula 和 Scoop manifest，并提交回 `main`。
- **Add formal MIT license file** — add `LICENSE` and link it from README so package managers and users can discover licensing directly / 新增正式 MIT `LICENSE` 文件，并在 README 中链接，方便包管理器和用户识别许可证。

### Verification / 验证

- `ruby -c Formula/flyssh.rb`
- `brew style Formula/flyssh.rb`
- `python3 -m json.tool bucket/flyssh.json`
- `python3 -m py_compile .github/scripts/update_package_manifests.py`
- `ruby -e 'require "yaml"; YAML.load_file(".github/workflows/release.yml")'`
- `git diff --check`

---

## v2.0.1 (2026-05-24)

### Bug Fixes / 修复

- **Clear the visible terminal screen when entering `--mosh`** — after the initial attach succeeds and the local terminal enters raw mode, FlySSH now clears the current visible screen once before starting the mosh output loop. This removes stale PowerShell/Windows Terminal content from the first mosh screen without clearing scrollback or affecting reconnect refresh behavior / 修复 `--mosh` 首次进入时 PowerShell/Windows Terminal 旧内容残留的问题：初次 attach 成功并进入 raw mode 后，启动 mosh 输出循环前只清一次当前可见屏，不清 scrollback，也不影响断线重连后的刷新逻辑。

### Verification / 验证

- `go test ./pkg/moshsession`
- `go test ./...`
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/flyssh-mosh-initial-clear.exe .`
- `git diff --check`

---

## v2.0.0 (2026-05-23)

### Major Release / 大版本发布

- **Celebrate built-in `--mosh` support** — this major release marks FlySSH's new mosh-over-FlySSH terminal mode as the headline capability. `flyssh ... --mosh` carries mosh datagrams through the existing SSH/SOCKS/multi-hop route, so interactive terminal sessions can recover without requiring direct UDP reachability to the final server / 庆祝内置 `--mosh` 支持：FlySSH 现在可以把 mosh datagram 封装进现有 SSH/SOCKS/多跳链路，在最终服务器无法 UDP 直连时仍能提供可恢复的交互式终端体验。
- **Document persistent named mosh sessions** — `--mosh-session NAME` is documented for cross-process takeover of the same remote PTY/shell with a fresh key, while normal same-process reconnect keeps the local mosh client state alive / 完善固定 mosh 会话文档：`--mosh-session NAME` 可跨进程接回同一个远端 PTY/shell，同进程断线则保留本地 mosh client 状态并重建 attach 通道。
- **Document implementation boundaries and differences from standard mosh** — README and `docs/MOSH.md` now describe usage, parameters, relay/daemon internals, the FlySSH-maintained `mosh-go` fork, unsupported scope, and operational notes / README 与 `docs/MOSH.md` 已补充用法、参数、relay/daemon 实现、`mosh-go` fork、未实现范围以及与标准 mosh 的差异。

### Verification / 验证

- `git diff --check`
- `go test ./pkg/cli ./pkg/moshsession ./cmd/relay`

---

## v1.0.43 (2026-05-23)

### Bug Fixes / 修复

- **Forward terminal input modes in `--mosh` sessions** — update the FlySSH-maintained `mosh-go` fork to `v0.5.2-flyssh.9`. The server now tracks and forwards application cursor-key mode (`ESC[?1h/l`) and application keypad mode (`ESC=` / `ESC>`) through framebuffer diffs, keeping the local terminal input mode aligned with full-screen programs such as `vi`/`vim` / `--mosh` 现在会同步全屏程序设置的 application cursor/keypad 模式，避免本地终端和远端程序的方向键/小键盘模式不一致。

### Verification / 验证

- `go test ./...` in `github.com/lovitus/mosh-go`
- `go test ./cmd/relay ./pkg/moshsession`
- `go test ./...`
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/flyssh-1.0.43-windows-amd64.exe .`

---

## v1.0.42 (2026-05-23)

### Bug Fixes / 修复

- **Fix `vi`/`vim` black screen in `--mosh` sessions** — update the FlySSH-maintained `mosh-go` fork to `v0.5.2-flyssh.8`. The server now forwards terminal query responses generated by the VT emulator back to the PTY, so full-screen programs that ask for cursor position or terminal status no longer block the mosh event loop / 修复 `--mosh` 中 `vi`/`vim` 黑屏、光标停在左上角且输入无效的问题；远端 server 会把 VT emulator 生成的终端查询应答写回 PTY，避免全屏程序等待 `ESC[6n` 等应答时卡住。

### Verification / 验证

- `go test ./...` in `github.com/lovitus/mosh-go`
- `go test ./cmd/relay ./pkg/moshsession`
- `go test ./...`
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/flyssh-1.0.42-windows-amd64.exe .`

---

## v1.0.41 (2026-05-23)

### Bug Fixes / 修复

- **Fix full-screen keyboard handling in Windows `--mosh` sessions** — Windows mosh sessions now explicitly enable virtual-terminal input on stdin after entering raw mode, so `vi`/`vim`/`less` and similar full-screen programs receive Esc, arrow keys, and other control sequences correctly. Terminal mode is restored on exit / 修复 Windows `--mosh` 会话中 `vi`/`vim` 等全屏程序按键控制异常的问题；进入 raw mode 后显式启用 stdin 的 VT input，并在退出时恢复终端模式。

### Verification / 验证

- `go test ./pkg/moshsession`
- `go test ./...`
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/flyssh-mosh-vt-input.exe .`

---

## v1.0.40 (2026-05-23)

### Bug Fixes / 修复

- **Fix stale fragments around prompts and full-screen programs in `--mosh`** — update the FlySSH-maintained `mosh-go` fork to `v0.5.2-flyssh.7`. Incremental framebuffer diffs now redraw changed rows from column 1 and clear blank suffixes, preventing stale text from remaining before or after prompts. The diff also synchronizes alternate screen transitions (`ESC[?1049h/l`) so programs like `top`, `vim`, and `less` do not leave their old screen in the normal PowerShell buffer / 修复 `--mosh` 在 PowerShell 中提示符前后、以及 `top`/`vim`/`less` 等全屏程序退出后残留旧画面的问题。

### Verification / 验证

- `go test ./...` in `github.com/lovitus/mosh-go`
- `go test ./cmd/relay ./pkg/moshsession`
- `go test ./...`
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/flyssh-1.0.40-windows-amd64.exe .`
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/flyssh-relay-mosh-screen-linux-amd64 ./cmd/relay`

---

## v1.0.39 (2026-05-23)

### Bug Fixes / 修复

- **Reduce stale screen residue in Windows PowerShell `--mosh` sessions** — update the FlySSH-maintained `mosh-go` fork to `v0.5.2-flyssh.6`, whose framebuffer diff now emits `ESC[K` when a changed row's suffix is blank. This clears old line tails during partial screen refreshes instead of relying only on overwriting spaces / 减少 Windows PowerShell 下 `--mosh` 局部刷新后旧内容残留的问题；`mosh-go` framebuffer diff 在行尾为空时会发送清行序列。

### Verification / 验证

- `go test ./...` in `github.com/lovitus/mosh-go`
- `go test ./cmd/relay ./pkg/moshsession`
- `go test ./...`
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/flyssh-1.0.39-windows-amd64.exe .`
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/flyssh-relay-mosh-display-linux-amd64 ./cmd/relay`

---

## v1.0.38 (2026-05-23)

### Bug Fixes / 修复

- **Fix `--mosh` attach handshake hang** — remote relay `-mosh-attach` now forwards the daemon `OK` handshake line back to the local FlySSH process before switching to framed datagrams. This fixes sessions that stopped after printing `flyssh: mosh session ... pid=...` / 修复 `--mosh` 在打印远端 session 和 pid 后卡住的问题；远端 relay 现在会先把 daemon 的 `OK` 握手行转发给本地 FlySSH，再进入 datagram 帧转发。
- **Add attach handshake timeout** — local attach setup now fails clearly after 10 seconds if the remote helper never returns the `OK` line, instead of waiting forever / 本地 attach 等待 `OK` 增加 10 秒超时，远端 helper 异常时不再无限等待。

### Verification / 验证

- `go test ./cmd/relay ./pkg/moshsession`
- `go test ./...`
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/flyssh-1.0.38-windows-amd64.exe .`
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/flyssh-relay-mosh-fix-linux-amd64 ./cmd/relay`

---

## v1.0.37 (2026-05-23)

### Features / 新功能

- **Add built-in `--mosh` over FlySSH** — `flyssh ... --mosh` now starts an embedded mosh-style terminal session whose datagrams are carried through the existing FlySSH SSH chain, SOCKS proxy, authentication, and relay helper path. This allows interactive terminal recovery without requiring direct UDP reachability to the final server / 新增内置 `--mosh` 模式：mosh datagram 通过 FlySSH 现有 SSH 多跳、SOCKS、认证和 relay helper 通道承载，不要求最终服务器 UDP 可直连。
- **Add persistent named mosh sessions** — `--mosh-session NAME` can reattach to an existing remote session by taking over the server association with a fresh key while keeping the remote PTY/shell alive. Same-process reconnects reuse the existing local mosh client state without takeover / 新增 `--mosh-session NAME` 固定会话：可用新 key 接管已有远端会话，同时保留远端 PTY/shell；同进程自动重连则复用本地 mosh client 状态。
- **Extend the embedded relay for mosh** — relay now supports internal `-mosh-start`, `-mosh-attach`, and `-mosh-daemon` commands on Linux, Darwin, and FreeBSD targets, with daemonized stdio isolation, 0700 runtime directories, session metadata, length-prefixed datagram framing, and bounded queues / 扩展内嵌 relay 支持 mosh 内部命令，并加入 daemon 脱离控制终端、运行目录权限、会话元数据、定长帧协议和有界队列。

### Hardening / 加固

- **Use the FlySSH-maintained `mosh-go` fork** — depend on `github.com/lovitus/mosh-go v0.5.2-flyssh.5`, which adds authenticated receive semantics, fragment accounting fixes, injected packet connections, and staged takeover (`PrepareTakeover` / `CommitTakeover`) so failed reattach attempts do not invalidate the previous client before attach succeeds / 使用 FlySSH 维护的 `mosh-go` fork，包含认证语义、分片 accounting、注入 packet conn 和两阶段 takeover 修复。
- **Keep SSH prompts out of raw terminal mode** — initial mosh start and attach now complete before switching stdin to raw mode, so password, host key, passphrase, and MFA prompts continue to run in the normal terminal / 首次 mosh start 和 attach 完成后才进入 raw mode，避免 SSH 交互提示在 raw terminal 下运行。

### Verification / 验证

- `go test ./cmd/relay ./pkg/moshsession`
- `go test ./...`
- `go test -race ./cmd/relay ./pkg/moshsession`
- `go test -race ./...`
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/flyssh-mosh-fix-windows-amd64.exe .`
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/flyssh-relay-mosh-fix-linux-amd64 ./cmd/relay`

---

## v1.0.36 (2026-05-21)

### Bug Fixes / 修复

- **Show the full Windows GUI connection route** — the `--wingui` connection field now shows the actual hop chain, including the final target, legacy `--secondhost` routes, and SOCKS proxy details, while keeping passwords redacted / 修复 Windows GUI 顶部连接摘要只显示首跳的问题；现在会展示完整 hop 链路、最终目标、legacy `--secondhost` 以及 SOCKS 代理信息，并继续隐藏密码。

### Verification / 验证

- `go test ./pkg/wingui`
- `go test ./...`
- `GOOS=windows GOARCH=amd64 go test -c ./pkg/wingui -o /tmp/wingui-connection-summary.test.exe`
- `GOOS=windows GOARCH=amd64 go build -o /tmp/flyssh-connection-summary.exe .`
- `git diff --check`

---

## v1.0.35 (2026-05-15)

### Bug Fixes / 修复

- **Fix `--help` drift and make `-c`/`-m` effective** — `--help` now documents the supported `--ssh-gateway`, `--help`, and `--version` flags, removes the unsupported `--key FILE` entry, and clarifies that `-c`/`-m` are comma-separated cipher/MAC lists. The `-c` and `-m` flags now populate `ResolvedConfig.Ciphers` / `ResolvedConfig.MACs`, while `-o Ciphers=...` and `-o MACs=...` continue to take highest priority / 修复 `--help` 与实际参数不同步的问题，并让 `-c` / `-m` 真正生效；同时保持 `-o Ciphers=...` / `-o MACs=...` 最高优先级。

### Verification / 验证

- `go test ./pkg/config ./pkg/cli`
- `go test ./...`
- `go build ./...`
- `GOOS=windows GOARCH=amd64 go build -o /tmp/flyssh-1.0.35-windows-amd64.exe .`
- `git diff --check`

---

## v1.0.34 (2026-05-13)

### Bug Fixes / 修复

- **Fix Ciphers/MACs not applied to ProxyJump hop connections** — `jumpConfig` in `connectViaJumpHost` was missing `ssh.Config`, so `-o Ciphers=...` had no effect when the ProxyJump hop itself is a legacy/embedded SSH server / 修复 ProxyJump 中间跳连接未应用 Ciphers/MACs 配置的问题。
- **Fix `-o Ciphers`/`-o MACs` unable to override ssh_config file settings** — `applyOption` had a `len()==0` guard copied from `applyEntry`, preventing CLI `-o` from overriding a `Host` block that already set `Ciphers`/`MACs`. Removed the guard; CLI `-o` now correctly takes highest priority (matches OpenSSH semantics) / 修复 `-o Ciphers=...` 无法覆盖 `~/.ssh/config` 中已有 Ciphers 配置的问题，符合 OpenSSH 优先级语义（CLI > 配置文件）。

### Verification / 验证

- `go build ./...`
- `go test ./...`

---

## v1.0.33 (2026-05-13)

### Bug Fixes / 修复

- **Fix Ciphers/MACs from ssh_config not being applied to SSH connections** — `Ciphers` and `MACs` directives in `~/.ssh/config` (or via `-o Ciphers=...`) were parsed into `ResolvedConfig` but never forwarded to `ssh.ClientConfig`. As a result, users configuring legacy ciphers (e.g. `aes128-cbc`) to reach old Dropbear/embedded SSH servers had no effect. Fix: `applyEntry` and `applyOption` in `pkg/config` now populate `ResolvedConfig.Ciphers`/`MACs`; `connectFirstHost` and `connectHop` in `main.go` now pass them to `ssh.ClientConfig.Config`. When not configured, both fields remain `nil` which preserves the existing behaviour of using Go crypto/ssh library defaults / 修复 ssh_config 里配置的 Ciphers/MACs 字段被解析但未传给 ssh.ClientConfig 的问题。现在可以通过 `-o Ciphers=aes128-cbc` 等配置连接旧版 Dropbear/嵌入式 SSH 服务器。未配置时保持原有默认行为不变。

### Verification / 验证

- `go build ./...`
- `go test ./...`

---

## v1.0.32 (2026-05-13)

### Bug Fixes / 修复

- **Fix SSH gateway incompatibility with GUI clients (XShell, PuTTY, etc.)** — the gateway now advertises three host key types: `ssh-ed25519`, `ecdsa-sha2-nistp256`, and `ssh-rsa`. Previously only `ssh-ed25519` was offered; older GUI clients that only accept `ssh-rsa` or ECDSA (e.g. XShell 5/6, PuTTY < 0.68) failed with "no common algorithm for host key". All three keys are persisted under `%APPDATA%/flyssh/` (`gateway_host_key`, `gateway_host_key_ecdsa`, `gateway_host_key_rsa`) so clients don't see a host key change on restart / 修复 SSH 网关与 GUI 客户端（XShell、PuTTY 等）不兼容的问题：网关现在同时提供 ed25519、ecdsa-sha2-nistp256、ssh-rsa 三种 host key，不再因为只提供 ed25519 而被老版本客户端拒绝。

### Verification / 验证

- `go build ./...`
- `go test ./...`
- Manual: XShell connects to gateway without "no common algorithm" error

---

## v1.0.31 (2026-05-12)

### Bug Fixes / 修复

- **Fix SSH gateway rsync hang (root cause: CloseWrite vs Close)** — rsync and some SSH clients hold their write side open until they receive `SSH_MSG_CHANNEL_CLOSE`, not just `SSH_MSG_CHANNEL_EOF`. The v1.0.30 fix sent only EOF (`CloseWrite`) after upstream closed, which created a deadlock: `wg.Wait()` blocked on `io.Copy(upCh, downCh)` which blocked on the client's write side which blocked on our CLOSE. Fix: after upstream EOF, drain exit-status (`upReqWg.Wait()`), then call `downCh.Close()` (full CLOSE) — this unblocks the client, which closes its write side, which unblocks the downstream→upstream goroutine / 修复 SSH 网关 rsync hang 根因：发送 CloseWrite（EOF）不够，rsync 等 SSH_MSG_CHANNEL_CLOSE 才会关自己的 write side。改为上游关闭后先等 exit-status 转发，再调 downCh.Close() 发完整 CLOSE，破解死锁。

### Verification / 验证

- `go build ./...`
- `go test ./...`
- Manual: rsync with files transferred — completes and prints stats without hanging
- Manual: rsync with no files to transfer (incremental, file unchanged) — exits immediately with stats
- Manual: `ssh`, `scp` — unaffected

---

## v1.0.30 (2026-05-12)

### Bug Fixes / 修复

- **Fix SSH gateway rsync hang after 100% transfer** — after a successful rsync transfer the session now exits immediately and prints the final stats line. Root cause: `exit-status` channel request was forwarded by a detached goroutine that could lose the race against `downCh.Close()`, leaving the client waiting for an exit code that never arrived. Fix: the upstream→downstream request goroutine is now waited on (`upReqWg`) after stdout finishes but before the downstream channel is closed, guaranteeing `exit-status` reaches the client. `upReqWg.Wait()` completes promptly because the SSH library closes `upReqs` when the upstream server sends `SSH_MSG_CHANNEL_CLOSE` (immediately after `exit-status` + EOF) / 修复 SSH 网关 rsync 传输 100% 后挂住的问题。根因：`exit-status` 请求由 detached goroutine 转发，可能在 `downCh.Close()` 之前输给调度竞争，导致客户端永远等不到退出码。修复：stdout 完成后增加 `upReqWg.Wait()`，确保上游请求（含 `exit-status`）全部转发给下游后再关闭通道。

### Verification / 验证

- `go build ./...`
- `go test ./...`
- Manual: `rsync -avzhP -e 'ssh -p 2222' file user@127.0.0.1:/tmp` completes and prints stats without hanging
- Manual: subsequent rsync runs (no-op incremental) also exit immediately

---

## v1.0.29 (2026-05-12)

### Bug Fixes / 修复

- **Fix SSH gateway session hang after SCP / exit** — after `scp` completes or the user types `exit`, the session now exits immediately instead of hanging for 30–60 seconds. Root cause: `handleSession` used a single `WaitGroup` for all 6 goroutines (stdout×2, stderr×2, request×2); stderr and request goroutines only unblock when channels are `Close()`d, but `Close()` was placed after `wg.Wait()`, creating a circular wait. Fix: stderr and request goroutines are now detached; only the two stdout `io.Copy` goroutines are waited on, after which `Close()` is called on both channels to immediately unblock the rest / 修复 SSH 网关会话在 SCP 传输完成或用户执行 `exit` 后挂住的问题。根因：`handleSession` 对全部 6 个 goroutine 共用同一个 `WaitGroup`，stderr 和 request goroutine 需要 channel `Close()` 才能退出，但 `Close()` 在 `wg.Wait()` 之后，造成循环等待。修复：stderr 和 request goroutine 改为后台运行不纳入等待，stdout 双向复制完成后立即 `Close()` 双向 channel。

### Verification / 验证

- `go build ./...`
- `go test ./...`
- Manual: `scp -P 2222` completes and exits immediately
- Manual: interactive `ssh` session `exit` returns immediately

---

## v1.0.28 (2026-05-12)

### Features / 功能

- **Add `--ssh-gateway` SSH gateway mode** — `--ssh-gateway 'user:pass@bind:port'` starts a local SSH server that proxies third-party SSH/SFTP clients (Xshell, SecureCRT, FileZilla, etc.) through FlySsh's established multi-hop connection. The client authenticates with local credentials; FlySsh handles the full upstream chain transparently. Implemented as a new zero-intrusion `pkg/gateway` package / 新增 `--ssh-gateway` SSH 网关模式：在本地启动一个 SSH 服务，将第三方 SSH/SFTP 客户端（Xshell、SecureCRT、FileZilla 等）通过 FlySsh 已建立的多跳连接透明代理。客户端仅需对本地网关认证，上游链路由 FlySsh 全权处理。以零侵入的新包 `pkg/gateway` 实现。

### Details / 细节

- Session channels: bidirectional data copy with directional request allowlists. `x11-req` and `auth-agent-req@openssh.com` are rejected / 会话通道：双向数据透明复制，按方向维护请求白名单；`x11-req` 和 `auth-agent-req@openssh.com` 明确拒绝。
- `direct-tcpip` channels use `forwarding.DialTCP` to preserve mux relay / exec fallback; `CloseWrite` properly propagated through `idleConn` / `direct-tcpip` 通道使用 `forwarding.DialTCP`；`CloseWrite` 正确穿透 `idleConn` 包装层。
- `keepalive@openssh.com` answered locally with `true`; `tcpip-forward` and unknown global requests return `false` / `keepalive@openssh.com` 本地回复 true；`tcpip-forward` 及未知全局请求返回 false。
- Gateway host key auto-generated (ed25519) and persisted to `os.UserConfigDir()/flyssh/gateway_host_key` (0600) / 网关主机密钥自动生成并持久化，重启不触发客户端密钥变更警告。
- Upstream disconnect closes listener and all active downstream connections / 上游断连时关闭监听器及所有活跃下游连接。
- Password auth uses `crypto/subtle.ConstantTimeCompare` / 密码认证使用常量时间比较。
- `--ssh-gateway` value scrubbed from `argv` at startup / 启动时从 `argv` 清除密码。
- CLI validates `--ssh-gateway` is mutually exclusive with `-A/-X/-Y/-N/-t/-T/-s/-L/-R/-D/-W/--wingui`/transfer/command/GUI-internal flags / CLI 校验互斥参数。

### Verification / 验证

- `go build ./...`
- `GOOS=windows GOARCH=amd64 go build ./...`
- `GOOS=windows GOARCH=arm64 go build ./...`
- `GOOS=linux GOARCH=amd64 go build ./...`
- `go test ./...`

---

## v1.0.27 (2026-05-11)

### Features / 功能

- **Allow mixed selections in the Windows companion GUI** — local and remote panes now allow selecting multiple files, multiple folders, or files and folders together while still enforcing a single transfer direction at a time / Windows 图形传输面板支持混合选择：本地和远端列表现在允许同时选择多个文件、多个文件夹或文件与文件夹混选，同时继续强制一次只能选择一个传输方向
- **Add `+Dir` folder creation controls** — both panes now expose `+Dir` to create one child directory under the current path; local folders use `os.Mkdir`, and remote folders use the existing thin subprocess command path with the standard `--` command separator / 新增 `+Dir` 新建目录按钮：左右两侧都可在当前路径下创建一级子目录；本地使用 `os.Mkdir`，远端沿用轻量子进程命令路径并使用标准 `--` 命令分隔符

### Improvements / 改进

- **Tighten GUI child-name validation** — selected item names and new folder names now reject path-like values such as `.`, `..`, `~`, slash/backslash paths, and Windows drive forms before generating transfer, delete, move, or mkdir commands / 收紧 GUI 子项名称校验：选中项名称和新目录名现在会在生成传输、删除、移动或建目录命令前拒绝 `.`, `..`, `~`、斜杠/反斜杠路径和 Windows 盘符路径形态
- **Shorten file operation button labels** — rename/move and delete controls are now shown as `MV` and `Del`, keeping the pane controls compact next to the path fields / 缩短文件操作按钮文案：重命名/移动与删除按钮现在显示为 `MV` 和 `Del`，让路径栏旁的面板控件更紧凑
- **Prefix companion GUI terminal logs** — subprocess command, spawn, exit-code, stdout, and stderr lines now include source prefixes in the terminal output while the GUI log remains available in-window / 为 companion GUI 终端日志添加来源前缀：子进程命令、启动、退出码、stdout 和 stderr 在终端输出中带来源标记，同时 GUI 窗口内日志继续可用

### Verification / 验证

- `go test -count=1 ./pkg/wingui`
- `go test -count=1 ./...`
- `go test -race -count=1 ./pkg/wingui ./pkg/transfer ./pkg/cli .`
- `GOOS=windows GOARCH=amd64 go build -o /tmp/flyssh-1.0.27-windows-amd64.exe .`

---

## v1.0.26 (2026-05-11)

### Bug Fixes / 修复

- **Fix Windows GUI rename/move target capture** — the rename dialog now captures the target path before closing the modal dialog, avoiding Walk control state loss that could report `rename target is empty` even after the field had been initialized / 修复 Windows GUI 重命名/移动目标路径读取：重命名对话框现在会在关闭模态窗口前读取目标路径，避免 Walk 控件状态在关闭后丢失导致已初始化的路径仍被报成 `rename target is empty`
- **Give file lists priority over the log area** — the Windows GUI now caps the log text area height and gives the main file panes a higher stretch factor, so resizing the window no longer lets logs consume space intended for the file lists / 文件列表优先于日志区域：Windows GUI 现在限制日志文本区最大高度，并提高主文件面板的伸展权重，窗口变高时日志不会继续占用文件列表空间

### Verification / 验证

- `go test -count=1 ./pkg/wingui`
- `go test -count=1 ./...`
- `GOOS=windows GOARCH=amd64 go build -o /tmp/flyssh-1.0.26-windows-amd64.exe .`

---

## v1.0.25 (2026-05-11)

### Docs / 文档

- **Document the remote command `--` separator** — README and CLI usage now explicitly describe `flyssh user@host -- <command>` for commands containing `@` or other text that could otherwise be parsed as an extra hop / 补充远程命令 `--` 分隔符文档：README 与 CLI usage 现在明确说明 `flyssh user@host -- <command>`，用于命令中包含 `@` 或其他可能被解析成额外跳点的文本

### Tests / 测试

- **Cover command separator error handling** — added coverage for rejecting `--` before any host is provided / 覆盖命令分隔符错误路径：新增测试确认未提供 host 时使用 `--` 会报错

### Verification / 验证

- `go test -count=1 ./pkg/cli`
- `go test -count=1 ./...`
- `GOOS=windows GOARCH=amd64 go build -o /tmp/flyssh-1.0.25-windows-amd64.exe .`

---

## v1.0.24 (2026-05-11)

### Bug Fixes / 修复

- **Fix Windows GUI remote delete and rename/move subprocess parsing** — remote delete/rename commands now pass through the standard `--` command separator so command text or paths containing `@` are not misclassified as extra SSH hops / 修复 Windows GUI 远端删除和重命名/移动的子进程解析：远端删除/重命名命令现在通过标准 `--` 命令分隔符传递，命令文本或路径中包含 `@` 时不会被误判为额外 SSH 跳点
- **Fix remote delete command construction** — the generated shell command no longer uses `"$@"`, avoiding the existing hop parser's `@` heuristic and preserving multi-target delete behavior / 修复远端删除命令构造：生成的 shell 命令不再使用 `"$@"`，避开现有 hop 解析器的 `@` 启发式，同时保留多目标删除能力
- **Fix rename dialog default target text** — the rename/move dialog now explicitly initializes the target path field after control creation, so accepting the default path no longer reports an empty target / 修复重命名对话框默认目标路径：重命名/移动对话框现在在控件创建后显式初始化目标路径，直接确认默认路径时不会再提示目标为空

### Verification / 验证

- `go test -count=1 ./pkg/cli ./pkg/wingui`
- `go test -count=1 ./...`
- `GOOS=windows GOARCH=amd64 go build -o /tmp/flyssh-delete-rename-fix.exe .`

---

## v1.0.23 (2026-05-11)

### Features / 功能

- **Add delete and rename/move controls to the Windows companion GUI** — local and remote panes now expose `Delete` and `Rename` buttons that enable only for valid selections; delete shows a confirmation preview, and rename edits the full path so it can also be used as a move operation / Windows 图形传输面板新增删除与重命名/移动：本地和远端面板都会在有效选择时启用 `Delete` 与 `Rename`；删除会显示确认预览，重命名可编辑完整路径，因此也可用于移动
- **Show remote Unix metadata in the Windows companion GUI** — remote listings now display best-effort `mode user:group` after the existing name, size, and time columns; unsupported targets leave the optional metadata blank without blocking browsing / Windows 图形传输面板显示远端 Unix 元数据：远端列表会在名称、大小、时间后追加 best-effort 的 `mode user:group`；目标机不支持时该增强字段留空，不影响浏览

### Improvements / 改进

- **Make unknown remote size/time explicit** — if remote `stat` cannot provide size or mtime, files now show `?` instead of silently treating the value as zero, and unknown values sort after known values / 明确显示未知的远端大小和时间：远端 `stat` 无法获取大小或修改时间时，文件显示 `?`，不再静默当作 0，排序时未知值排在已知值之后
- **Keep GUI actions on the thin subprocess path** — remote delete and rename/move are executed through spawned FlySsh subprocess commands, matching the existing companion GUI architecture and avoiding new session/auth backends / GUI 操作继续保持轻量子进程架构：远端删除和重命名/移动通过 FlySsh 子进程命令执行，沿用现有 companion GUI 设计，不新增 session/auth 后端
- **Improve button legibility** — Windows GUI buttons now use a bolder font while keeping the existing layout and control sizing / 改进按钮可读性：Windows GUI 按钮改为更粗字体，同时保持现有布局和控件尺寸

### Verification / 验证

- `go test -count=1 ./pkg/wingui`
- `go test -count=1 ./...`
- `GOOS=windows GOARCH=amd64 go build -o /tmp/flyssh-1.0.23-windows-amd64.exe .`
- `GOOS=windows GOARCH=amd64 go test -c ./pkg/wingui -o /tmp/wingui-1.0.23.test.exe`

---

## v1.0.22 (2026-05-10)

### Features / 功能

- **Add drag-and-drop uploads to the Windows companion GUI** — users can drag local files or folders onto the remote file list, review the target directory and selected paths, then choose `rsync`, `SCP`, or `Cancel`; invalid drops are rejected as a whole before any transfer starts / Windows 图形传输面板支持拖拽上传：可将本地文件或文件夹拖到远端列表，确认目标目录和路径后选择 `rsync`、`SCP` 或取消；存在无效路径时会整体拒绝，不会部分上传

### Improvements / 改进

- **Keep drag-drop uploads on the thin subprocess path** — drop uploads reuse the existing `--scp-upload` / `--rsync-upload` subprocess transfer flow, including SCP `-r` for folders and rsync `-avh`, without introducing a new transfer backend / 拖拽上传继续走轻量子进程路径：复用现有 `--scp-upload` / `--rsync-upload` 传输流程，目录场景自动使用 SCP `-r`，rsync 使用 `-avh`，不新增传输后端
- **Improve Windows GUI readability** — controls and list fonts are larger, file panes use fixed-width metadata columns, command previews avoid noisy POSIX quote escapes, and the log area is shorter so the file panes have more room / 改进 Windows GUI 可读性：按钮和列表字体加大，文件列表使用固定宽度元数据列，命令预览不再显示冗长的 POSIX 引号转义，日志区域缩短以给文件列表更多空间

### Verification / 验证

- `go test ./pkg/wingui`
- `go test ./...`
- `GOOS=windows GOARCH=amd64 go build -o /tmp/flyssh-1.0.22-review.exe .`
- `GOOS=windows GOARCH=amd64 go test -c ./pkg/wingui -o /tmp/wingui-1.0.22-drop-upload.test.exe`

---

## v1.0.21 (2026-05-10)

### Bug Fixes / 修复

- **Preserve option values that look like GUI/runtime flags** — GUI child-process argument cleanup now strips only real `--wingui`, `--version`, and `-V` flags while preserving values consumed by options such as `--password --wingui`, `--passwords -V`, or `-o -V` / 保留看起来像 GUI/版本标志的参数值：GUI 子进程参数清理现在只移除真正的 `--wingui`、`--version`、`-V` 标志，不会误删 `--password --wingui`、`--passwords -V`、`-o -V` 等被其他选项消费的值
- **Normalize drive-relative local transfer paths** — local Windows paths such as `D:folder\file` are normalized to `D:\folder\file` before browsing or transfer generation, avoiding ambiguous drive-relative semantics / 规范化 Windows 盘符相对路径：本地路径如 `D:folder\file` 在浏览或生成传输参数前会规范化为 `D:\folder\file`，避免盘符相对路径语义不明确

### Improvements / 改进

- **Add size/time metadata to the Windows companion GUI** — local and remote panes now show formatted size and modification time alongside names / Windows 图形传输面板显示大小和时间信息：本地与远端列表现在在名称旁展示格式化的大小和修改时间
- **Add sortable file panes** — local and remote panes can sort by name, modification time, or size while keeping directories first / 文件列表支持排序：本地和远端面板可按名称、修改时间或大小排序，并保持目录优先
- **Improve GUI log usability** — the log area now auto-scrolls to new output and includes a clear button / 改进 GUI 日志体验：日志区会自动滚动到新输出，并提供清空按钮

### Verification / 验证

- `go test ./...`
- `GOOS=windows GOARCH=amd64 go build -o /tmp/flyssh-wingui-review-amd64.exe .`
- `GOOS=windows GOARCH=arm64 go build -o /tmp/flyssh-wingui-review-arm64.exe .`

---

## v1.0.20 (2026-05-10)

### Bug Fixes / 修复

- **Fix Windows rsync downloads to drive-letter directories** — local Windows targets such as `E:\aria2-down` are no longer passed to Cygwin/cwRsync as `./E:\...`, which produced invalid paths like `/cygdrive/e/./E:\...`; FlySsh now converts drive-letter paths to the local rsync runtime's POSIX mount style / 修复 Windows rsync 下载到盘符目录失败：本地目标如 `E:\aria2-down` 不再被传成会导致 `/cygdrive/e/./E:\...` 的 `./E:\...` 形式，而是转换为当前 rsync 运行时支持的 POSIX 挂载路径
- **Probe Windows rsync path style before transfer** — FlySsh now tries read-only `rsync --list-only` probes for `/cygdrive/x/...` and `/x/...` styles and caches the working style per `rsync.exe`, with MSYS2/Cygwin/cwRsync path heuristics kept as fallback / Windows rsync 传输前探测路径风格：先通过只读 `rsync --list-only` 探测 `/cygdrive/x/...` 与 `/x/...` 哪种可用，并按 `rsync.exe` 缓存结果；MSYS2/Cygwin/cwRsync 目录和 DLL 判断作为兜底
- **Avoid Walk list panic on empty remote directories** — GUI file lists now provide a placeholder row for empty listings so refreshing or entering an empty directory does not crash the Windows companion GUI / 避免空远端目录导致 Walk 列表 panic：GUI 文件列表为空时显示占位行，刷新或进入空目录不再崩溃

### Improvements / 改进

- **Improve Windows companion GUI transfer controls** — SCP and rsync are now shown as separate direction-aware buttons, the remote path field is visible in the remote pane, and the log area supports scrolling / 改进 Windows 图形传输面板：SCP 与 rsync 改为带方向的独立按钮，远端路径框显示在远端面板内，日志区支持滚动
- **Show redacted child commands before GUI transfers** — GUI logs now preview the spawned FlySsh command while redacting inline and flag-based passwords / GUI 传输前显示脱敏后的子命令：日志中预览实际启动的 FlySsh 子进程命令，同时隐藏内联密码和密码参数
- **Use more informative default rsync flags from the GUI** — GUI rsync transfers now use `-avh` by default instead of only `-a` / GUI rsync 默认参数更清晰：默认使用 `-avh`，不再只使用 `-a`

### Verification / 验证

- `go test ./pkg/transfer`
- `go test ./pkg/wingui`
- `go test ./...`
- `go test -race ./pkg/transfer ./pkg/wingui`
- `GOOS=windows GOARCH=amd64 go build ./...`

---

## v1.0.19 (2026-05-10)

### Bug Fixes / 修复

- **Fix rsync transport on Windows — overlapped stdin handle** — when rsync (MSYS2, Cygwin, or cwRsync) forks flyssh as the `-e` transport, the inherited stdin pipe is opened for overlapped (async) I/O.  Go's `os.Stdin.Read` calls `ReadFile` with a nil `OVERLAPPED` pointer, which is invalid for async handles (Windows error 87 "The parameter is incorrect").  A new `rawStdinReader()` reads via the Windows `ReadFile` API with a proper `OVERLAPPED` struct, fixing the root cause (Go issue [#15388](https://github.com/golang/go/issues/15388)) / 修复 Windows 上 rsync 传输失败：rsync（MSYS2/Cygwin/cwRsync）fork flyssh 作为 `-e` 传输时，stdin pipe 被设为 overlapped I/O 模式，Go 的 `os.Stdin.Read` 传 nil `OVERLAPPED` 导致 error 87。新增 `rawStdinReader()` 使用带 `OVERLAPPED` 结构体的 `ReadFile` 调用修复此问题

### Improvements / 改进

- **Improved Windows rsync detection** — rsync is now searched in: (1) flyssh.exe directory, (2) current working directory, (3) `%PATH%`, (4) well-known MSYS2/Cygwin/cwRsync/ICW paths.  When not found, actionable install instructions are printed / Windows rsync 检测增强：依次从 flyssh.exe 同目录、当前工作目录、`%PATH%`、已知安装路径查找 rsync，未找到时输出安装指引

### Docs / 文档

- **Windows rsync prerequisites documented** — README now includes a dedicated section on Windows rsync setup, explaining the overlapped I/O limitation and supported rsync sources / README 新增 Windows rsync 前置条件章节，说明 overlapped I/O 限制及支持的 rsync 来源

### Verification / 验证

- `go build ./...`
- `GOOS=windows go build ./...`
- `go test ./...`
- Live Windows test: 57 MB rsync upload with Chinese-character paths succeeded (MSYS2 rsync + Cygwin rsync)

---

## v1.0.18 (2026-05-10)

### Bug Fixes / 修复

- **Fix rsync "both remote" error on Windows drive-letter paths** — local paths like `E:\folder\file` are now prefixed with `./` before being passed to rsync, preventing the drive letter + colon from being misinterpreted as a remote host specification / 修复 Windows 盘符路径被 rsync 误判为远程：本地路径如 `E:\folder\file` 在传给 rsync 前加 `./` 前缀，防止盘符冒号被当作远程主机标记

---

## v1.0.17 (2026-05-10)

### Bug Fixes / 修复

- **Fix SOCKS5 dynamic forward partial-read and buffer overflow** — the built-in SOCKS5 server now uses `io.ReadFull` for all protocol reads instead of `conn.Read`, preventing partial-read misparses on slow or fragmented TCP streams; domain-name address reads are also moved to a dedicated buffer to avoid a panic when the domain length approaches the 255-byte SOCKS5 maximum / 修复动态转发内置 SOCKS5 服务端的协议读取问题：所有协议读取改用 `io.ReadFull`，防止 TCP 分片导致的协议解析错误；域名地址读取移至独立缓冲区，避免域名接近 255 字节上限时发生越界 panic
- **Strip version flags from GUI transfer subprocesses** — `buildChildArgs` now filters `--version` and `-V` in addition to `--wingui`, so transfer and browse child processes no longer exit at the version-print branch in `main.go` / GUI 传输子进程不再携带版本标志：`buildChildArgs` 现在同时过滤 `--version` 和 `-V`，避免子进程在 `main.go` 的版本打印分支提前退出
- **Fix `unescapeStr` comment accuracy** — the doc comment now correctly states that all quote characters are stripped (not just surrounding ones) and that literal quotes in passwords must be backslash-escaped / 修正 `unescapeStr` 注释描述：准确说明该函数剥除所有引号字符，密码中的字面引号需用反斜杠转义

### Features / 功能

- **Windows rsync detection with install hints** — on Windows, `resolveRsyncBinary` now checks `%PATH%` (including Scoop), then probes MSYS2, Cygwin, and cwRsync install directories; if rsync is still not found, actionable installation instructions are printed to stderr / Windows 下 rsync 自动探测与安装提示：依次检查 `%PATH%`（含 Scoop）、MSYS2、Cygwin、cwRsync 目录，均未找到时输出安装指引
- **GUI rsync availability check improved** — the Windows GUI now uses the same multi-path rsync detection so the "rsync" transfer option is correctly enabled when rsync is installed outside `%PATH%` / Windows GUI rsync 可用性检测增强：复用多路径探测逻辑，rsync 安装在非 PATH 位置时也能正确启用

### Verification / 验证

- `go build ./...`
- `go test -race ./...`

---

## v1.0.16 (2026-04-12)

### Fixes / 修复

- **Propagate SSH host-key options to later multi-hop hops** — follow-up hops now resolve their own SSH config and CLI `-o` overrides instead of using a hand-built partial config, so `StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`, and similar host-key settings work consistently beyond the first hop / 修复多跳后续 hop 未继承 SSH 主机密钥相关配置的问题：后续跳点现在会重新解析各自的 SSH 配置与 CLI `-o` 覆盖项，而不再使用手工拼接的不完整配置，因此 `StrictHostKeyChecking=no`、`UserKnownHostsFile=/dev/null` 等设置不再只对第一跳生效
- **Keep per-hop key selection isolated** — when `--keys` is used, later hops no longer accidentally inherit the first hop's explicit key while still honoring a hop-specific key assignment / 修复逐跳密钥隔离：使用 `--keys` 时，后续 hop 不会再意外继承第一跳的显式密钥，同时仍会正确使用分配给该 hop 的专属密钥

### Verification / 验证

- Added regression coverage in [main_multihop_integration_test.go](/Users/fanli/flyssh/main_multihop_integration_test.go) for per-hop SSH option inheritance and key isolation
- `go test ./...`
- `go test -race ./...`
- Live repro with `node2 -> node3`: `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null` now reaches `node3` successfully without a second-hop changed-key prompt / 实机验证 `node2 -> node3`：带 `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null` 时已可直接到达 `node3`，不会再出现第二跳 changed-key 提示

---

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
