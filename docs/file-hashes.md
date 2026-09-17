# File hashes in the Windows transfer GUI

Both the Local and Remote toolbars have **+Dir | Hash | MV | Del**.
Select one or more files in one pane, click **Hash**, choose an algorithm, and
click **Calculate**. The default is SHA-256. MD5, SHA-1, SHA-224, SHA-384 and
SHA-512 are also available. Cancel closes the chooser without reading any files.

Hash is disabled for an empty selection, folders, mixed file/folder selections,
a pane without a current directory, and while another operation is running.
Hashing does not recurse into folders. The selected paths are captured before
the chooser opens, so later selection or navigation changes cannot redirect the
operation. Hashing runs on a worker goroutine, leaving the window responsive.

Each successful result appears in the **Log** and the terminal, as
`checksum  filename`. Filenames containing backslashes, carriage returns or
newlines use the GNU checksum escaped-filename convention (a leading backslash
before the checksum, and escaped characters in the filename). Errors are
reported for each failed file; the remaining selected files are still processed.
A partial or failed read is never presented as a successful checksum. Closing
the window cancels local hashing and terminates the remote child process.

Local files are streamed through Go's hash implementations with bounded memory;
no external Windows checksum program is required. Remote files are read and
hashed **on the remote host**, over the same FlySSH route and authentication as
other remote operations. File contents are not downloaded. Remote hashing uses
an available `*sum` utility, `shasum` for SHA algorithms, a BSD hash utility, or
OpenSSL. A missing or incompatible utility produces a visible error. Long
selections are batched to stay within the Windows child-command size limit.

Only regular files (including links to regular files) are hashed. A file that
changes during hashing has no snapshot guarantee. MD5 and SHA-1 are provided for
compatibility with existing checksums, not for authentication.

## Verification

Linux CI runs portable tests for all six algorithms, binary streaming,
cancellation, shell quoting, unusual filenames, command batching, utility
fallbacks and per-file failures. Windows GUI CI runs Windows selection and
subprocess tests, builds both Windows architectures in release mode, extracts
the amd64 ZIP and drives the actual executable's native controls against a
loopback SSH fixture. It checks button placement and enablement, chooser default
and cancellation, all six methods in both panes, and partial failures.

To test a downloaded Windows release with Git Bash installed:

```powershell
$env:FLYSSH_GUI_BINARY = 'C:\path\to\flyssh.exe'
$env:FLYSSH_GUI_TEST_ARTIFACTS = 'C:\path\to\validation'
go test ./e2e -run '^TestWindowsGUIHashes$' -count=1 -v -timeout 5m
```

Tests use temporary directories and fixture-only SSH credentials. They never
access a personal SSH server or personal files. Windows arm64 is cross-built;
runtime GUI verification runs on Windows amd64.
