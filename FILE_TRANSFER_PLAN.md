# File Transfer Plan

## Status

Implemented and validated on 2026-04-05.

This document is kept as design and implementation traceability. The plan items below are now complete in the current codebase (`pkg/transfer`, `pkg/cli`, `main.go`) with live verification recorded in `VALIDATION_REPORT_2026-04-05.md`.

## Goal

Add file transfer support to `flyssh` with two explicit modes:

- `rsync` as a wrapper around the local system `rsync`
- `scp` as a built-in implementation over the existing SSH connection chain

The design keeps connection/authentication under outer `flyssh` control and prevents transfer arguments from redefining transport.

## User-Facing CLI

Exactly one of these flags may be used at a time:

- `--rsync-upload '...'`
- `--rsync-download '...'`
- `--scp-upload '...'`
- `--scp-download '...'`

Examples:

```bash
flyssh user:pass@host --rsync-upload '-avzhP --dry-run ./src/ /data/app/'
flyssh user:pass@host --rsync-download '-avzhP /data/app/ ./src/'

flyssh user:pass@host --scp-upload '-r a.txt b.txt dir1 /remote/targetdir'
flyssh user:pass@host --scp-download '-r /remote/a /remote/b ./localdir'
```

## Core Rules

- Outer `flyssh` arguments own all connection details: host, hops, SOCKS, keys, passwords.
- Transfer argument blocks must not redefine transport.
- Transfer mode disables reconnect and PTY by default.
- Transfer mode does not run interactive shell or regular remote command mode.

## Parsing Rules

Transfer argument blocks are shell-split into tokens.

Then:

1. Parse supported flags for the selected protocol.
2. For `rsync`, consume option arguments using an explicit option-spec table.
3. For `scp`, parse supported flags and then collect remaining path operands.
4. Require at least two path operands.
5. Treat the last operand as the target.
6. Treat all preceding operands as sources.

This makes both protocols support `n:1` source-to-destination behavior.

## Validation Rules

Reject transfer arguments containing explicit remote transport overrides:

- `-e`
- `--rsh`
- `scp://...`
- `rsync://...`

Reject remote path operands inside the transfer block, for example:

- `user@host:path`
- `host:path`

Exception:

- Do not treat Windows local drive paths like `C:\src` or `D:\tmp\file.txt` as remote specs.
- Remote-spec detection must distinguish Windows drive letters from SSH-style `host:path`.
- First-pass remote-spec detection is intentionally conservative:
  - if a `/` or `\` appears before `:`, treat the operand as a local path
  - if `:` appears before any `/` or `\`, reject the operand as remote-like
  - a leading `:` is also rejected
- As a tradeoff, first-pass transfer parsing does not support local path operands with a bare colon before any path separator, such as `a:b`.

Additional first-pass `rsync` rejects:

- `--files-from`
- `--from0`

Additional first-pass `scp` rejects:

- `-3`
- remote-to-remote copy forms

## Authentication Behavior

Transfers must reuse outer `flyssh` authentication and routing:

- inline passwords
- `--password`
- `--passwords`
- key files
- SOCKS
- multi-hop

No second SSH password prompt should appear during transfer.

## Execution Model

### rsync

`flyssh` invokes the local system `rsync` and injects a transport command via `-e`.

User transfer arguments must not include remote specs, but `flyssh` still needs a
remote operand when invoking the local `rsync` binary.

Implementation rule:

- `flyssh` constructs an internal placeholder remote operand for local `rsync`
- the placeholder is not user-controlled
- the injected internal flyssh transport takes over the real connection path
- remote-spec validation applies only to user-supplied transfer arguments, not to the internal placeholder
- before full implementation, `flyssh` adds probe coverage to confirm how the local `rsync` binary passes argv into the configured `-e` transport command

The injected internal flyssh mode:

- establishes the SSH chain
- connects to the final host
- runs the remote rsync server command
- transparently pipes stdin/stdout/stderr

This preserves rsync compatibility without reimplementing the rsync protocol.

### scp

`flyssh` implements the SCP client side directly:

- upload: run remote `scp -t <target>` using a safely shell-escaped target path
- download: run remote `scp -f <source>` using a safely shell-escaped source path
- build the remote exec command from a fixed command template and a separately escaped single path argument
- do not shell-escape the entire command as one opaque string
- preserve literal path bytes as much as possible so spaces and shell metacharacters do not change meaning
- support multi-source copy into a destination directory
- support recursive directory transfer with `-r` or `-R`

## Proposed Code Structure

- `pkg/transfer/spec.go`
  - transfer mode selection
  - transfer tokenization
  - validation
  - normalized `TransferSpec`
- `pkg/transfer/rsync.go`
  - local rsync wrapper
  - internal transport invocation
- `pkg/transfer/scp.go`
  - SCP protocol implementation
- `pkg/transfer/errors.go`
  - user-facing validation errors

CLI updates:

- extend `pkg/cli/cli.go` options and parsing

Main flow updates:

- detect transfer mode in `main.go`
- after final client creation, dispatch to transfer path first

## Development Task List

### Phase 1: CLI and Transfer Spec

Tasks:

- Add four transfer fields to `cli.Options`.
- Enforce mutual exclusion for the four transfer flags.
- Implement transfer mode detection helper.
- Add shell-style tokenization for transfer argument blocks.
- Add normalized `TransferSpec` model.
- Add validation helpers for illegal transport redefinition.
- Add `rsync` option-spec parsing so option arguments are consumed before operand extraction.
- Add Windows-aware and separator-aware remote-spec detection so `C:\...` remains a local path.
- Add parser tests for:
  - valid upload/download blocks
  - multi-source handling
  - mutual exclusion
  - illegal `-e`
  - illegal remote specs
  - Windows drive-path handling
  - local paths containing `:` after a path separator
  - rejection of bare-colon local names such as `a:b`
  - too few operands

Acceptance:

- CLI can parse exactly one transfer mode.
- Valid examples normalize into a consistent `TransferSpec`.
- `rsync` option arguments are not misclassified as source or destination paths.
- Invalid transport arguments fail with clear errors.

### Phase 2: Main Dispatch and Transfer Runtime Contract

Tasks:

- Add transfer dispatch branch in `runOnce`.
- Force transfer mode to disable reconnect.
- Force transfer mode to avoid PTY allocation.
- Ensure verbose/log output does not corrupt stdout protocol streams.
- Add an internal mode placeholder for rsync transport.
- Define how internal placeholder remote operands are generated for local `rsync`.
- Add a pre-implementation probe for local `rsync -e` argv behavior and lock the internal transport contract to the observed behavior.

Acceptance:

- Transfer mode exits before shell/command execution.
- No reconnect loop happens in transfer mode.
- Transfer mode keeps stdin/stdout/stderr clean.

### Phase 3: Built-In SCP

Tasks:

- Implement local SCP upload engine.
- Implement local SCP download engine.
- Support single file upload/download.
- Support multi-source to destination directory.
- Support recursive mode via `-r` and `-R`.
- Support preserve mode basics via `-p`.
- Add filesystem validation for multi-source destination semantics.
- Add testkit support for fake remote SCP behavior.
- Add integration tests for:
  - upload file
  - download file
  - upload multiple files
  - download multiple files
  - recursive directory upload/download
  - remote paths beginning with `-`
  - remote paths containing spaces or shell metacharacters
  - remote paths containing quotes
  - remote paths containing glob characters
  - invalid multi-source destination

Acceptance:

- SCP works over existing final-hop SSH connection.
- No extra SSH auth prompt occurs.
- Multi-source rules behave predictably.

### Phase 4: Rsync Wrapper

Tasks:

- Implement local rsync wrapper executor.
- Detect missing local `rsync` binary and fail clearly.
- Add a probe test or fixture that captures how local `rsync` invokes the configured `-e` transport.
- Inject internal flyssh transport command with connection arguments.
- Construct an internal placeholder remote operand for local `rsync`.
- Implement hidden internal transport mode that:
  - rebuilds connection options
  - connects to final host
  - runs the remote rsync server command
  - pipes stdio
- Validate forbidden `rsync` options before local exec.
- Add tests for:
  - local `rsync -e` argv-shape probe coverage
  - argument normalization
  - forbidden option rejection
  - internal transport command generation
  - missing local rsync error path

Acceptance:

- `--rsync-upload` and `--rsync-download` launch local `rsync` with flyssh-managed transport.
- User never needs to provide `-e`.
- Remote host specs inside the transfer block are rejected.
- Internal placeholder remote operands are hidden from user input validation and exist only to satisfy local `rsync` invocation requirements.
- Internal transport argv handling is based on probe-backed behavior rather than assumptions.

### Phase 5: Documentation

Tasks:

- Update `README.md` with transfer section and examples.
- Document first-pass limitations.
- Document Windows requirement for local `rsync`.
- Document that reconnect is disabled in transfer modes.

Acceptance:

- README reflects final CLI.
- Limitations are explicit and non-surprising.

## Deferred Work

Not in first implementation:

- remote-to-remote transfers
- rsync daemon mode
- rsync `--files-from`
- transfer resume after reconnect
- zmodem
- full OpenSSH scp flag parity

## Suggested Implementation Order

1. Phase 1
2. Phase 2
3. Phase 3
4. Phase 4
5. Phase 5

This order reduces coupling and gets a fully native `scp` path working before the rsync wrapper is layered on top.

## Testing Expectation

This feature must ship with broad automated coverage, not just happy-path tests.

At minimum, tests should cover:

- parser normalization and rejection behavior
- multi-source semantics
- Windows-path and colon-path edge cases
- remote paths with spaces, quotes, glob characters, and leading `-`
- SCP upload and download integration flows
- recursive SCP flows
- rsync wrapper argument generation
- local `rsync -e` transport invocation shape
- failure paths for invalid arguments and missing local dependencies
