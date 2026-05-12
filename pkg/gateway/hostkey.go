package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// loadOrGenerateHostKey returns an SSH host key signer.
// The key is persisted to os.UserConfigDir()/flyssh/gateway_host_key so that
// third-party clients don't see a host key change on every restart.
func loadOrGenerateHostKey() (ssh.Signer, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("gateway host key: config dir: %w", err)
	}
	keyDir := filepath.Join(dir, "flyssh")
	keyPath := filepath.Join(keyDir, "gateway_host_key")

	data, err := os.ReadFile(keyPath)
	if err == nil {
		signer, err := ssh.ParsePrivateKey(data)
		if err == nil {
			return signer, nil
		}
		// Corrupted key — regenerate below.
	}

	// Generate new ed25519 key.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gateway host key: generate: %w", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("gateway host key: marshal: %w", err)
	}
	pemData := pem.EncodeToMemory(pemBlock)

	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("gateway host key: mkdir: %w", err)
	}
	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		return nil, fmt.Errorf("gateway host key: write: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(pemData)
	if err != nil {
		return nil, fmt.Errorf("gateway host key: parse generated: %w", err)
	}
	return signer, nil
}
