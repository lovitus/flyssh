package transfer

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func runSCP(client *ssh.Client, spec *Spec) (int, error) {
	cfg := parseSCPFlags(spec.Flags)
	switch spec.Direction {
	case DirectionUpload:
		return scpUpload(client, spec, cfg)
	case DirectionDownload:
		return scpDownload(client, spec, cfg)
	default:
		return 1, fmt.Errorf("unsupported scp direction: %s", spec.Direction)
	}
}

type scpConfig struct {
	recursive bool
	preserve  bool
}

func parseSCPFlags(flags []string) scpConfig {
	var cfg scpConfig
	for _, token := range flags {
		if !strings.HasPrefix(token, "-") || token == "--" {
			continue
		}
		for _, ch := range token[1:] {
			switch ch {
			case 'r', 'R':
				cfg.recursive = true
			case 'p':
				cfg.preserve = true
			}
		}
	}
	return cfg
}

func scpUpload(client *ssh.Client, spec *Spec, cfg scpConfig) (int, error) {
	if err := validateUploadSources(spec.Sources, cfg); err != nil {
		return 1, err
	}

	session, err := client.NewSession()
	if err != nil {
		return 1, fmt.Errorf("create scp upload session: %w", err)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return 1, fmt.Errorf("scp upload stdin: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return 1, fmt.Errorf("scp upload stdout: %w", err)
	}
	var stderr bytes.Buffer
	session.Stderr = &stderr

	cmd := buildSCPCopyCommand("-t", spec.Target, cfg, len(spec.Sources) > 1)
	if err := session.Start(cmd); err != nil {
		return 1, fmt.Errorf("start remote scp upload: %w", err)
	}

	writer := bufio.NewWriter(stdin)
	reader := bufio.NewReader(stdout)

	if err := readSCPAck(reader); err != nil {
		_ = stdin.Close()
		return finishSession(session, stderr.String(), fmt.Errorf("scp upload handshake: %w", err))
	}

	for _, source := range spec.Sources {
		if err := sendLocalPath(writer, reader, source, cfg); err != nil {
			_ = stdin.Close()
			return finishSession(session, stderr.String(), err)
		}
	}
	if err := writer.Flush(); err != nil {
		_ = stdin.Close()
		return finishSession(session, stderr.String(), fmt.Errorf("flush scp upload stream: %w", err))
	}
	if err := stdin.Close(); err != nil {
		return finishSession(session, stderr.String(), fmt.Errorf("close scp upload stream: %w", err))
	}
	return finishSession(session, stderr.String(), nil)
}

func scpDownload(client *ssh.Client, spec *Spec, cfg scpConfig) (int, error) {
	if len(spec.Sources) > 1 {
		info, err := os.Stat(spec.Target)
		if err != nil || !info.IsDir() {
			return 1, fmt.Errorf("multiple sources require the destination to be a directory")
		}
	}

	for _, source := range spec.Sources {
		if code, err := scpDownloadOne(client, source, spec.Target, len(spec.Sources) > 1, cfg); err != nil {
			return code, err
		}
	}
	return 0, nil
}

func scpDownloadOne(client *ssh.Client, remoteSource, localTarget string, forceDir bool, cfg scpConfig) (int, error) {
	session, err := client.NewSession()
	if err != nil {
		return 1, fmt.Errorf("create scp download session: %w", err)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return 1, fmt.Errorf("scp download stdin: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return 1, fmt.Errorf("scp download stdout: %w", err)
	}
	var stderr bytes.Buffer
	session.Stderr = &stderr

	cmd := buildSCPCopyCommand("-f", remoteSource, cfg, false)
	if err := session.Start(cmd); err != nil {
		return 1, fmt.Errorf("start remote scp download: %w", err)
	}

	reader := bufio.NewReader(stdout)
	writer := bufio.NewWriter(stdin)
	if err := writeSCPAck(writer); err != nil {
		return finishSession(session, stderr.String(), err)
	}

	root, err := prepareDownloadRoot(localTarget, remoteSource, forceDir)
	if err != nil {
		_ = stdin.Close()
		return finishSession(session, stderr.String(), err)
	}
	if err := receiveIntoRoot(reader, writer, root, cfg); err != nil {
		_ = stdin.Close()
		if !cfg.recursive && strings.Contains(err.Error(), "not a regular file") {
			err = fmt.Errorf("remote source is a directory; use -r to copy directories")
		}
		return finishSession(session, stderr.String(), err)
	}

	if err := stdin.Close(); err != nil {
		return finishSession(session, stderr.String(), fmt.Errorf("close scp download stream: %w", err))
	}
	return finishSession(session, stderr.String(), nil)
}

func validateUploadSources(sources []string, cfg scpConfig) error {
	for _, source := range sources {
		info, err := os.Stat(source)
		if err != nil {
			return fmt.Errorf("stat %s: %w", source, err)
		}
		if info.IsDir() && !cfg.recursive {
			return fmt.Errorf("source %s is a directory; use -r to copy directories", source)
		}
	}
	return nil
}

func buildSCPCopyCommand(mode, remotePath string, cfg scpConfig, forceDir bool) string {
	var parts []string
	parts = append(parts, "scp")
	if cfg.recursive {
		parts = append(parts, "-r")
	}
	if cfg.preserve {
		parts = append(parts, "-p")
	}
	if forceDir {
		parts = append(parts, "-d")
	}
	parts = append(parts, mode, shellEscape(remoteCommandPath(remotePath)))
	return strings.Join(parts, " ")
}

func remoteCommandPath(p string) string {
	if p != "" && p[0] == '-' {
		return "./" + p
	}
	return p
}

func sendLocalPath(w *bufio.Writer, r *bufio.Reader, source string, cfg scpConfig) error {
	info, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("stat %s: %w", source, err)
	}
	name := filepath.Base(source)

	if cfg.preserve {
		if err := sendPreserveTimes(w, r, info); err != nil {
			return err
		}
	}

	if info.IsDir() {
		if err := sendDirStart(w, r, name, info.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(source)
		if err != nil {
			return fmt.Errorf("read dir %s: %w", source, err)
		}
		for _, entry := range entries {
			child := filepath.Join(source, entry.Name())
			if err := sendLocalPath(w, r, child, cfg); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, "E\n"); err != nil {
			return fmt.Errorf("write dir end: %w", err)
		}
		if err := w.Flush(); err != nil {
			return fmt.Errorf("flush dir end: %w", err)
		}
		return readSCPAck(r)
	}

	file, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open %s: %w", source, err)
	}
	defer file.Close()

	if _, err := fmt.Fprintf(w, "C%04o %d %s\n", info.Mode().Perm(), info.Size(), name); err != nil {
		return fmt.Errorf("write file header: %w", err)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush file header: %w", err)
	}
	if err := readSCPAck(r); err != nil {
		return err
	}
	if _, err := io.Copy(w, file); err != nil {
		return fmt.Errorf("copy file data: %w", err)
	}
	if err := w.WriteByte(0); err != nil {
		return fmt.Errorf("write file trailer: %w", err)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush file data: %w", err)
	}
	return readSCPAck(r)
}

func sendDirStart(w *bufio.Writer, r *bufio.Reader, name string, perm os.FileMode) error {
	if _, err := fmt.Fprintf(w, "D%04o 0 %s\n", perm, name); err != nil {
		return fmt.Errorf("write dir header: %w", err)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush dir header: %w", err)
	}
	return readSCPAck(r)
}

func sendPreserveTimes(w *bufio.Writer, r *bufio.Reader, info os.FileInfo) error {
	modTime := info.ModTime()
	atime := modTime
	if _, err := fmt.Fprintf(w, "T%d 0 %d 0\n", modTime.Unix(), atime.Unix()); err != nil {
		return fmt.Errorf("write preserve header: %w", err)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush preserve header: %w", err)
	}
	return readSCPAck(r)
}

type downloadRoot struct {
	baseDir string
	asDir   bool
}

type downloadDir struct {
	path  string
	times *fileTimes
}

func prepareDownloadRoot(localTarget, remoteSource string, forceDir bool) (downloadRoot, error) {
	if forceDir {
		return downloadRoot{baseDir: localTarget, asDir: true}, nil
	}

	if info, err := os.Stat(localTarget); err == nil && info.IsDir() {
		return downloadRoot{baseDir: filepath.Join(localTarget, path.Base(remoteSource)), asDir: false}, nil
	}

	return downloadRoot{baseDir: localTarget, asDir: false}, nil
}

func receiveIntoRoot(r *bufio.Reader, w *bufio.Writer, root downloadRoot, cfg scpConfig) error {
	stack := []downloadDir{{path: root.baseDir}}
	var pendingTimes *fileTimes
	rootStarted := false

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read scp control stream: %w", err)
		}
		if line == "" {
			continue
		}
		switch line[0] {
		case 0:
			continue
		case 1, 2:
			return fmt.Errorf("remote scp error: %s", strings.TrimSpace(line[1:]))
		case 'T':
			times, err := parseTimes(line)
			if err != nil {
				return err
			}
			pendingTimes = &times
			if err := writeSCPAck(w); err != nil {
				return err
			}
		case 'D':
			if !cfg.recursive {
				return fmt.Errorf("remote source is a directory; use -r to copy directories")
			}
			mode, name, err := parseFileHeader(line)
			if err != nil {
				return err
			}
			parent := stack[len(stack)-1].path
			target := parent
			if root.asDir || len(stack) > 1 {
				target, err = joinPathWithinRoot(parent, name)
				if err != nil {
					return err
				}
			}
			if err := os.MkdirAll(target, mode); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
			dir := downloadDir{path: target, times: pendingTimes}
			pendingTimes = nil
			if len(stack) == 1 {
				rootStarted = true
			}
			stack = append(stack, dir)
			if err := writeSCPAck(w); err != nil {
				return err
			}
		case 'E':
			if len(stack) > 1 {
				dir := stack[len(stack)-1]
				if dir.times != nil {
					_ = os.Chtimes(dir.path, dir.times.atime, dir.times.mtime)
				}
				stack = stack[:len(stack)-1]
			}
			if err := writeSCPAck(w); err != nil {
				return err
			}
			if rootStarted && len(stack) == 1 {
				return nil
			}
		case 'C':
			mode, name, size, err := parseCopyHeader(line)
			if err != nil {
				return err
			}
			parent := stack[len(stack)-1].path
			target := parent
			if root.asDir || len(stack) > 1 {
				target, err = joinPathWithinRoot(parent, name)
				if err != nil {
					return err
				}
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("mkdir parent %s: %w", filepath.Dir(target), err)
			}
			if err := writeSCPAck(w); err != nil {
				return err
			}
			if err := receiveFile(r, target, mode, size, pendingTimes); err != nil {
				return err
			}
			pendingTimes = nil
			if err := writeSCPAck(w); err != nil {
				return err
			}
			if len(stack) == 1 {
				return nil
			}
		default:
			return fmt.Errorf("unexpected scp control record: %q", strings.TrimSpace(line))
		}
	}
}

func joinPathWithinRoot(base, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("invalid remote filename: empty")
	}
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("invalid remote filename %q: absolute paths are not allowed", name)
	}
	cleanName := filepath.Clean(name)
	if cleanName == "." || cleanName == ".." || strings.HasPrefix(cleanName, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("invalid remote filename %q: path escapes target directory", name)
	}

	target := filepath.Join(base, cleanName)
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("resolve target directory: %w", err)
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", fmt.Errorf("resolve target path: %w", err)
	}
	rel, err := filepath.Rel(absBase, absTarget)
	if err != nil {
		return "", fmt.Errorf("validate target path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("invalid remote filename %q: path escapes target directory", name)
	}
	return target, nil
}

type fileTimes struct {
	mtime time.Time
	atime time.Time
}

func parseTimes(line string) (fileTimes, error) {
	fields := strings.Fields(strings.TrimSpace(line[1:]))
	if len(fields) != 4 {
		return fileTimes{}, fmt.Errorf("bad scp time record: %q", strings.TrimSpace(line))
	}
	mtime, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return fileTimes{}, fmt.Errorf("bad scp mtime: %w", err)
	}
	atime, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return fileTimes{}, fmt.Errorf("bad scp atime: %w", err)
	}
	return fileTimes{mtime: time.Unix(mtime, 0), atime: time.Unix(atime, 0)}, nil
}

func parseFileHeader(line string) (os.FileMode, string, error) {
	mode, name, _, err := parseHeaderCommon(line)
	return mode, name, err
}

func parseCopyHeader(line string) (os.FileMode, string, int64, error) {
	return parseHeaderCommon(line)
}

func parseHeaderCommon(line string) (os.FileMode, string, int64, error) {
	line = strings.TrimSpace(line)
	if len(line) < 2 {
		return 0, "", 0, fmt.Errorf("bad scp control record: %q", line)
	}
	fields := strings.SplitN(line[1:], " ", 3)
	if len(fields) != 3 {
		return 0, "", 0, fmt.Errorf("bad scp header: %q", line)
	}
	modeValue, err := strconv.ParseUint(fields[0], 8, 32)
	if err != nil {
		return 0, "", 0, fmt.Errorf("bad scp mode: %w", err)
	}
	sizeValue, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, "", 0, fmt.Errorf("bad scp size: %w", err)
	}
	return os.FileMode(modeValue), fields[2], sizeValue, nil
}

func receiveFile(r *bufio.Reader, target string, mode os.FileMode, size int64, times *fileTimes) error {
	file, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", target, err)
	}
	defer file.Close()

	if _, err := io.CopyN(file, r, size); err != nil {
		return fmt.Errorf("read file payload: %w", err)
	}
	ack, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("read file terminator: %w", err)
	}
	if ack != 0 {
		msg, _ := r.ReadString('\n')
		return fmt.Errorf("remote scp error: %s", strings.TrimSpace(string(ack)+msg))
	}
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("chmod %s: %w", target, err)
	}
	if times != nil {
		if err := os.Chtimes(target, times.atime, times.mtime); err != nil {
			return fmt.Errorf("chtimes %s: %w", target, err)
		}
	}
	return nil
}

func readSCPAck(r *bufio.Reader) error {
	code, err := r.ReadByte()
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1, 2:
		msg, _ := r.ReadString('\n')
		return fmt.Errorf("%s", strings.TrimSpace(msg))
	default:
		return fmt.Errorf("unexpected scp ack byte: %d", code)
	}
}

func writeSCPAck(w *bufio.Writer) error {
	if err := w.WriteByte(0); err != nil {
		return fmt.Errorf("write scp ack: %w", err)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush scp ack: %w", err)
	}
	return nil
}

func finishSession(session *ssh.Session, stderr string, prior error) (int, error) {
	waitErr := session.Wait()
	if prior != nil {
		if waitErr != nil {
			if stderr != "" {
				return 1, fmt.Errorf("%v: %s", prior, strings.TrimSpace(stderr))
			}
		}
		return 1, prior
	}
	if waitErr == nil {
		return 0, nil
	}
	if exitErr, ok := waitErr.(*ssh.ExitError); ok {
		if stderr != "" {
			return exitErr.ExitStatus(), errors.New(strings.TrimSpace(stderr))
		}
		return exitErr.ExitStatus(), nil
	}
	if stderr != "" {
		return 1, errors.New(strings.TrimSpace(stderr))
	}
	return 1, waitErr
}

func shellEscape(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
