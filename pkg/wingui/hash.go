package wingui

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"strings"
)

type hashMethod struct {
	name  string
	label string
}

// Keep the choice list and the command allowlist together. No user-supplied
// algorithm name is ever interpolated into a remote shell command.
func hashMethods() []hashMethod {
	return []hashMethod{
		{"md5", "MD5 (md5sum)"},
		{"sha1", "SHA-1 (sha1sum)"},
		{"sha224", "SHA-224 (sha224sum)"},
		{"sha256", "SHA-256 (sha256sum)"},
		{"sha384", "SHA-384 (sha384sum)"},
		{"sha512", "SHA-512 (sha512sum)"},
	}
}

func newFileHasher(method string) (hash.Hash, error) {
	switch method {
	case "md5":
		return md5.New(), nil // File checksums, not authentication.
	case "sha1":
		return sha1.New(), nil // Compatibility with existing checksum files.
	case "sha224":
		return sha256.New224(), nil
	case "sha256":
		return sha256.New(), nil
	case "sha384":
		return sha512.New384(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported hash method: %q", method)
	}
}

// hashLocalFile streams a regular file with bounded memory. A result is only
// returned after a successful read of the entire file; partial hashes are never
// presented as successes. Symlinks to regular files are followed.
func hashLocalFile(ctx context.Context, method, filename string) (string, error) {
	h, err := newFileHasher(method)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	info, err := os.Stat(filename)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file: %q", filename)
	}
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file: %q", filename)
	}
	if _, err := io.CopyBuffer(h, hashContextReader{ctx, f}, make([]byte, 128*1024)); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type hashContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r hashContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// Match the checksum tools' escaped-filename convention, keeping each result on
// one line even when a remote filename contains newlines or backslashes.
func escapeHashFilename(filename string) string {
	return strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\r", "\\r").Replace(filename)
}

func formatHashResult(digest, filename string) string {
	escaped := escapeHashFilename(filename)
	prefix := ""
	if escaped != filename {
		prefix = "\\"
	}
	return prefix + digest + "  " + escaped
}

// Leave headroom for Windows command-line quoting and the connection arguments.
const maxRemoteHashCommandBytes = 8000

func buildRemoteHashCommands(method string, targets []string) ([]string, error) {
	h, err := newFileHasher(method)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no selected hash targets")
	}

	// Select a server-side utility once per batch. Input redirection avoids
	// interpreting filenames as options and gives all backends the same output.
	var script strings.Builder
	script.WriteString("LC_ALL=C; export LC_ALL\n")
	fmt.Fprintf(&script, "if command -v %ssum >/dev/null 2>&1; then\n  flyssh_hash() { %ssum; }\n", method, method)
	if method != "md5" {
		fmt.Fprintf(&script, "elif command -v shasum >/dev/null 2>&1; then\n  flyssh_hash() { shasum -a %s; }\n", strings.TrimPrefix(method, "sha"))
	}
	fmt.Fprintf(&script, "elif command -v %s >/dev/null 2>&1; then\n  flyssh_hash() { %s -q; }\n", method, method)
	fmt.Fprintf(&script, "elif command -v openssl >/dev/null 2>&1; then\n  flyssh_hash() { openssl dgst -%s -r; }\n", method)
	fmt.Fprintf(&script, "else\n  printf 'hash failed: no compatible %s utility found on the remote host\\n' >&2\n  exit 127\nfi\n", method)
	script.WriteString("expected=" + strconv.Itoa(h.Size()*2) + "\n")
	script.WriteString(`flyssh_hash_one() {
  if [ ! -f "$1" ]; then
    printf 'hash failed: not a regular file: %s\n' "$2" >&2
    return 1
  fi
  if digest=$(flyssh_hash < "$1"); then
    digest=${digest%% *}
    case "$digest" in
      ''|*[!0-9a-fA-F]*)
        printf 'hash failed: invalid digest for %s\n' "$2" >&2
        return 1 ;;
    esac
    if [ "${#digest}" -ne "$expected" ]; then
      printf 'hash failed: invalid digest length for %s\n' "$2" >&2
      return 1
    fi
    prefix=
    [ "$1" = "$2" ] || prefix='\'
    printf '%s%s  %s\n' "$prefix" "$digest" "$2"
  else
    printf 'hash failed: could not read or hash %s\n' "$2" >&2
    return 1
  fi
}
result=0
while [ "$#" -gt 1 ]; do
  flyssh_hash_one "$1" "$2" || result=1
  shift 2
done
exit "$result"
`)
	prefix := "sh -c " + shellQuote(script.String()) + " flyssh-hash"
	var commands []string
	command := prefix
	for _, target := range targets {
		if target == "" || strings.ContainsRune(target, '\x00') {
			return nil, fmt.Errorf("invalid hash target: %q", target)
		}
		args := " " + shellQuote(target) + " " + shellQuote(escapeHashFilename(target))
		if len(prefix)+len(args) > maxRemoteHashCommandBytes {
			return nil, fmt.Errorf("hash target is too long: %q", target)
		}
		if len(command)+len(args) > maxRemoteHashCommandBytes {
			commands = append(commands, command)
			command = prefix
		}
		command += args
	}
	return append(commands, command), nil
}
