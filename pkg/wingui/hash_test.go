package wingui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHashLocalFileKnownVectors(t *testing.T) {
	vectors := []struct{ method, empty, abc string }{
		{"md5", "d41d8cd98f00b204e9800998ecf8427e", "900150983cd24fb0d6963f7d28e17f72"},
		{"sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "a9993e364706816aba3e25717850c26c9cd0d89d"},
		{"sha224", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
		{"sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"sha384", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
		{"sha512", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
	}
	for _, v := range vectors {
		t.Run(v.method, func(t *testing.T) {
			for input, want := range map[string]string{"": v.empty, "abc": v.abc} {
				file := filepath.Join(t.TempDir(), "file with spaces and 'quote' 数据.txt")
				if err := os.WriteFile(file, []byte(input), 0600); err != nil {
					t.Fatal(err)
				}
				got, err := hashLocalFile(context.Background(), v.method, file)
				if err != nil || got != want {
					t.Fatalf("input %q: got %q, %v; want %s", input, got, err, want)
				}
			}
		})
	}
	if len(hashMethods()) != len(vectors) {
		t.Fatal("every offered method must have known-vector coverage")
	}
}

func TestHashLocalFileStreamsLargeBinary(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789\x00\xff\r\n"), 600000)
	file := filepath.Join(t.TempDir(), "large.bin")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := hashLocalFile(context.Background(), "sha256", file)
	want := fmt.Sprintf("%x", sha256.Sum256(data))
	if err != nil || got != want {
		t.Fatalf("got %q, %v; want %s", got, err, want)
	}
}

func TestHashLocalFileErrorsAndCancellation(t *testing.T) {
	dir := t.TempDir()
	for _, file := range []string{dir, filepath.Join(dir, "missing")} {
		if got, err := hashLocalFile(context.Background(), "sha256", file); err == nil || got != "" {
			t.Fatalf("invalid file %q returned %q, %v", file, got, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := hashLocalFile(ctx, "sha256", filepath.Join(dir, "missing")); !errors.Is(err, context.Canceled) || got != "" {
		t.Fatalf("canceled hash returned %q, %v", got, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	r := hashContextReader{ctx, &cancelOnRead{cancel: cancel}}
	if _, err := io.Copy(io.Discard, r); !errors.Is(err, context.Canceled) {
		t.Fatalf("stream cancellation: %v", err)
	}
	want := errors.New("read failed")
	if _, err := io.Copy(io.Discard, hashContextReader{context.Background(), hashFailReader{want}}); !errors.Is(err, want) {
		t.Fatalf("read error not propagated: %v", err)
	}
}

type cancelOnRead struct{ cancel context.CancelFunc }

func (r *cancelOnRead) Read(p []byte) (int, error) {
	p[0] = 'x'
	r.cancel()
	return 1, nil
}

type hashFailReader struct{ err error }

func (r hashFailReader) Read([]byte) (int, error) { return 0, r.err }

func TestHashAllowlistAndInvalidTargets(t *testing.T) {
	for _, method := range []string{"", "SHA256", "sha256sum", "sha256; touch injected", "md4"} {
		if _, err := newFileHasher(method); err == nil {
			t.Fatalf("accepted method %q", method)
		}
		if _, err := buildRemoteHashCommands(method, []string{"/tmp/a"}); err == nil {
			t.Fatalf("accepted remote method %q", method)
		}
	}
	for _, paths := range [][]string{nil, {""}, {"/tmp/ok", "bad\x00name"}, {strings.Repeat("x", maxRemoteHashCommandBytes)}} {
		if commands, err := buildRemoteHashCommands("sha256", paths); err == nil || commands != nil {
			t.Fatalf("accepted invalid targets: %q, %v", commands, err)
		}
	}
}

func TestFormatHashResult(t *testing.T) {
	for _, tt := range []struct{ name, want string }{
		{"a b.txt", "abcd  a b.txt"},
		{"a\nb\rc\\d", "\\abcd  a\\nb\\rc\\\\d"},
		{"C:\\data\\a.bin", "\\abcd  C:\\\\data\\\\a.bin"},
	} {
		if got := formatHashResult("abcd", tt.name); got != tt.want {
			t.Fatalf("got %q, want %q", got, tt.want)
		}
	}
}

func hashTestShell(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX utility integration runs on Unix; Windows GUI is tested separately")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("POSIX shell unavailable")
	}
	return sh
}

func runHashTestCommand(t *testing.T, sh, command, dir, pathEnv string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(sh, "-c", command)
	cmd.Dir = dir
	if pathEnv != "" {
		cmd.Env = []string{"PATH=" + pathEnv, "LC_ALL=C"}
	}
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	err := cmd.Run()
	return out.String(), stderr.String(), err
}

func TestRemoteHashesRealUtilitiesAndQuoting(t *testing.T) {
	sh := hashTestShell(t)
	dir := t.TempDir()
	names := []string{"plain", "empty", "with space ' quote", "-leading-option", "$(touch injected);`touch injected`", "数据.txt", "line\nbreak\rback\\slash"}
	var paths []string
	for _, name := range names {
		file := filepath.Join(dir, name)
		data := []byte("abc")
		if name == "empty" {
			data = nil
		}
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, file)
	}
	for _, method := range hashMethods() {
		t.Run(method.name, func(t *testing.T) {
			if _, err := exec.LookPath(method.name + "sum"); err != nil {
				t.Skip(err)
			}
			commands, err := buildRemoteHashCommands(method.name, paths)
			if err != nil {
				t.Fatal(err)
			}
			var got, want strings.Builder
			for _, command := range commands {
				out, stderr, err := runHashTestCommand(t, sh, command, dir, "")
				if err != nil {
					t.Fatalf("remote command: %v: %s", err, stderr)
				}
				got.WriteString(out)
			}
			for _, file := range paths {
				digest, err := hashLocalFile(context.Background(), method.name, file)
				if err != nil {
					t.Fatal(err)
				}
				want.WriteString(formatHashResult(digest, file) + "\n")
			}
			if got.String() != want.String() {
				t.Fatalf("got %q, want %q", got.String(), want.String())
			}
		})
	}
	if _, err := os.Stat(filepath.Join(dir, "injected")); !os.IsNotExist(err) {
		t.Fatal("a filename was executed as shell syntax")
	}
}

func TestRemoteHashContinuesAfterFileErrors(t *testing.T) {
	sh := hashTestShell(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "good")
	if err := os.WriteFile(file, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	commands, err := buildRemoteHashCommands("sha256", []string{file, filepath.Join(dir, "missing"), dir, file})
	if err != nil {
		t.Fatal(err)
	}
	out, stderr, err := runHashTestCommand(t, sh, commands[0], dir, "")
	if err == nil || !strings.Contains(stderr, "not a regular file") || strings.Count(out, "  "+file+"\n") != 2 {
		t.Fatalf("must report errors and hash later files: out=%q stderr=%q err=%v", out, stderr, err)
	}
}

func TestRemoteHashFallbacksAndMissingUtility(t *testing.T) {
	sh := hashTestShell(t)
	for _, backend := range []string{"shasum", "openssl", "missing", "bad-output"} {
		t.Run(backend, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(sh, filepath.Join(bin, "sh")); err != nil {
				t.Fatal(err)
			}
			if backend == "bad-output" {
				if err := os.WriteFile(filepath.Join(bin, "sha256sum"), []byte("#!/bin/sh\nprintf 'not-a-checksum\\n'\n"), 0700); err != nil {
					t.Fatal(err)
				}
			} else if backend != "missing" {
				utility, err := exec.LookPath(backend)
				if err != nil {
					t.Skip(err)
				}
				if err := os.Symlink(utility, filepath.Join(bin, backend)); err != nil {
					t.Fatal(err)
				}
			}
			file := filepath.Join(dir, "file")
			if err := os.WriteFile(file, []byte("abc"), 0600); err != nil {
				t.Fatal(err)
			}
			for _, method := range hashMethods() {
				if (backend == "shasum" && method.name == "md5") || (backend == "bad-output" && method.name != "sha256") {
					continue
				}
				commands, err := buildRemoteHashCommands(method.name, []string{file})
				if err != nil {
					t.Fatal(err)
				}
				out, stderr, err := runHashTestCommand(t, sh, commands[0], dir, bin)
				if backend == "missing" || backend == "bad-output" {
					if err == nil || out != "" || !strings.Contains(stderr, "hash failed:") {
						t.Fatalf("invalid backend succeeded: %q, %q, %v", out, stderr, err)
					}
					continue
				}
				digest, localErr := hashLocalFile(context.Background(), method.name, file)
				if localErr != nil || err != nil || out != formatHashResult(digest, file)+"\n" {
					t.Fatalf("%s via %s: out=%q stderr=%q err=%v local=%v", method.name, backend, out, stderr, err, localErr)
				}
			}
		})
	}
}

func TestRemoteHashLargeSelectionIsBatched(t *testing.T) {
	sh := hashTestShell(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "file with spaces")
	if err := os.WriteFile(file, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 200)
	for i := range paths {
		paths[i] = file
	}
	commands, err := buildRemoteHashCommands("sha256", paths)
	if err != nil || len(commands) < 2 {
		t.Fatalf("not batched: %d, %v", len(commands), err)
	}
	lines := 0
	for _, command := range commands {
		if len(command) > maxRemoteHashCommandBytes {
			t.Fatalf("oversized command: %d", len(command))
		}
		out, stderr, err := runHashTestCommand(t, sh, command, dir, "")
		if err != nil {
			t.Fatalf("batch failed: %s, %v", stderr, err)
		}
		lines += strings.Count(out, "\n")
	}
	if lines != len(paths) {
		t.Fatalf("hashed %d of %d files", lines, len(paths))
	}
}
