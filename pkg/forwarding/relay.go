package forwarding

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

//go:embed relaybin/relay-*.gz
var relayBinFS embed.FS

// Per-arch decompressed binary cache (shared across clients, immutable once loaded)
var (
	archBinMu    sync.Mutex
	archBinCache = make(map[string][]byte) // "linux-amd64" -> binary
	archBinHash  = make(map[string]string) // "linux-amd64" -> sha256 hex prefix
)

// getOrUploadRelay detects the remote arch, uploads the embedded relay binary
// if needed, and returns the remote path. Uses per-client state (cs) so each
// hop in a multi-hop chain gets independent tracking.
func getOrUploadRelay(client *ssh.Client, cs *clientState, verbose bool) (string, error) {
	// If already uploaded for this client, verify it's still there
	if cs.relayUploaded && cs.relayPath != "" {
		if checkRemoteExists(client, cs.relayPath) {
			return cs.relayPath, nil
		}
		cs.relayUploaded = false
	}

	// Detect remote arch (cached per-client)
	if cs.relayArch == "" {
		arch, err := detectRemoteArch(client)
		if err != nil {
			return "", fmt.Errorf("detect arch: %w", err)
		}
		cs.relayArch = arch
	}

	// Load decompressed binary for this arch (globally cached, thread-safe)
	binData, hashPrefix, err := getRelayBinary(cs.relayArch)
	if err != nil {
		return "", err
	}

	cs.relayPath = fmt.Sprintf("/tmp/.flyssh-relay-%s", hashPrefix)

	// Hash-based cache: if remote file name matches, binary is identical — skip upload
	if checkRemoteExists(client, cs.relayPath) {
		cs.relayUploaded = true
		if verbose {
			log.Printf("Relay: cached binary at %s (hash match, skip upload)", cs.relayPath)
		}
		return cs.relayPath, nil
	}

	// Upload
	if err := uploadBinary(client, cs.relayPath, binData); err != nil {
		return "", fmt.Errorf("upload relay: %w", err)
	}

	cs.relayUploaded = true
	log.Printf("Relay: uploaded %s binary to %s (%d bytes)", cs.relayArch, cs.relayPath, len(binData))
	return cs.relayPath, nil
}

// getRelayBinary returns the decompressed binary and hash prefix for arch.
func getRelayBinary(arch string) ([]byte, string, error) {
	archBinMu.Lock()
	defer archBinMu.Unlock()

	if bin, ok := archBinCache[arch]; ok {
		return bin, archBinHash[arch], nil
	}

	bin, err := loadEmbeddedRelay(arch)
	if err != nil {
		return nil, "", err
	}

	h := sha256.Sum256(bin)
	prefix := fmt.Sprintf("%x", h[:8])
	archBinCache[arch] = bin
	archBinHash[arch] = prefix
	return bin, prefix, nil
}

// detectRemoteArch runs "uname -sm" and maps to a Go os-arch string.
func detectRemoteArch(client *ssh.Client) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	out, err := sess.Output("uname -sm")
	if err != nil {
		return "", fmt.Errorf("uname: %w", err)
	}

	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 2 {
		return "", fmt.Errorf("unexpected uname output: %q", string(out))
	}

	osName := strings.ToLower(fields[0])
	archName := strings.ToLower(fields[1])

	goos := ""
	switch {
	case strings.Contains(osName, "linux"):
		goos = "linux"
	case strings.Contains(osName, "darwin"):
		goos = "darwin"
	case strings.Contains(osName, "freebsd"):
		goos = "freebsd"
	}

	goarch := ""
	switch archName {
	case "x86_64", "amd64":
		goarch = "amd64"
	case "aarch64", "arm64":
		goarch = "arm64"
	case "i386", "i686", "x86":
		goarch = "386"
	case "armv6l", "armv7l", "armhf", "arm":
		goarch = "arm"
	}

	if goos == "" || goarch == "" {
		return "", fmt.Errorf("unsupported relay platform: %s/%s (relay skipped, will use other fallbacks)", osName, archName)
	}
	return goos + "-" + goarch, nil
}

// loadEmbeddedRelay loads and decompresses the gzipped relay binary for the given arch.
func loadEmbeddedRelay(arch string) ([]byte, error) {
	name := "relaybin/relay-" + arch + ".gz"
	data, err := relayBinFS.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("no embedded relay for %s: %w", arch, err)
	}

	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decompress relay: %w", err)
	}
	defer gz.Close()

	bin, err := io.ReadAll(gz)
	if err != nil {
		return nil, fmt.Errorf("decompress relay: %w", err)
	}
	return bin, nil
}

// checkRemoteExists checks if a file exists and is executable on the remote.
func checkRemoteExists(client *ssh.Client, path string) bool {
	sess, err := client.NewSession()
	if err != nil {
		return false
	}
	defer sess.Close()
	return sess.Run("test -x "+path) == nil
}

// uploadBinary uploads binary data to the remote host at the given path.
func uploadBinary(client *ssh.Client, path string, data []byte) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}

	cmd := fmt.Sprintf("cat > %s && chmod +x %s", path, path)
	if err := sess.Start(cmd); err != nil {
		return fmt.Errorf("start upload: %w", err)
	}

	if _, err := stdin.Write(data); err != nil {
		return fmt.Errorf("write data: %w", err)
	}
	stdin.Close()

	if err := sess.Wait(); err != nil {
		return fmt.Errorf("upload wait: %w", err)
	}
	return nil
}
