# Validation Report 2026-04-05

This document records the live validation performed for the file transfer work added to `flyssh`.

Sensitive connection details are intentionally excluded from this file.

## Scope

The validation covered:

- transfer CLI parsing and conflict handling
- SCP upload and download
- rsync upload and download
- single-hop and multi-hop transfer paths
- password-based auth variants including per-hop password lists
- host key auto-accept behavior on fresh nodes
- expected error paths such as wrong password and invalid transfer combinations

## Test Assets

Four disposable SSH targets were used:

- `node1`: wrong-password / auth-failure validation target
- `node2`: SSH target used as first hop and single-hop transfer target
- `node3`: SSH target used as second-hop transfer target
- `node4`: SSH target with normal file permissions used to confirm clean rsync/scp behavior

Environment-specific note:

- `node2` and `node3` allow transfers, but rsync uploads may return exit code `23` because the remote filesystem rejects permission updates on rsync temp files. File contents still arrive correctly.
- `node4` has normal permissions and was used to confirm that the rsync upload path succeeds cleanly without that environment-specific error.

## Code Fixes Verified

The following bugs were found during live validation and fixed:

1. `--passwords` did not correctly supply the first hop password.
2. Connection planning mutated the original CLI options, which could duplicate key material across reconnects.
3. Multi-hop host key verification could panic when the host key callback received a nil remote address.

The fixes are backed by automated coverage in:

- [main_multihop_integration_test.go](./main_multihop_integration_test.go)
- [auth_test.go](./pkg/auth/auth_test.go)

## Scenarios Validated

### CLI and Local Validation

Validated by automated tests and local execution:

- transfer flag mutual exclusion
- transfer mode conflicts with remote command, `-N`, `-W`, and forwarding
- rsync transport override rejection (`-e` / `--rsh`)
- remote-like operand rejection
- SCP and rsync transfer argument parsing
- per-hop password and key mapping
- repeatable connection planning without option mutation

### Authentication and Routing

Validated live:

- direct password auth
- `--password-env`
- `--password-file`
- `--passwords` single-hop
- `--passwords` multi-hop
- legacy `--secondhost`
- inline multi-hop credentials
- SOCKS routing through a local temporary SOCKS forward

### SCP

Validated live:

- single-hop upload
- single-hop download
- multi-hop upload
- multi-hop download

Validated by automated integration tests:

- recursive upload and download
- preserve mode (`-p`)
- multi-source upload and download
- paths with spaces
- paths with leading `-`
- error on directory download without `-r`
- error on upload to a missing parent path

### rsync

Validated live:

- single-hop upload to a normal-permission target
- single-hop download
- multi-hop upload
- multi-hop download

Validated by automated tests:

- local wrapper argument shape
- internal transport option encoding/decoding
- missing local `rsync` binary handling
- transport override rejection

## Outcomes

### Confirmed Working

- SCP single-hop and multi-hop transfer flow
- rsync single-hop and multi-hop transfer flow
- hidden internal rsync transport entry path
- per-hop password assignment including first hop
- host key auto-accept for newly seen hosts

### Environment-Specific Observations

- rsync uploads on permission-restricted targets can return `23` even when file contents are transferred successfully.
- This behavior did not reproduce on the normal-permission target, which indicates an environment issue rather than a flyssh protocol issue.

## Final Assessment

The transfer implementation is now logically consistent and validated across real single-hop and multi-hop environments.
Documentation status:

- `README.md` transfer section has been completed with end-user examples, conflict rules, and environment caveats.
