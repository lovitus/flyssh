package gateway

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// loadOrGenerateHostKeys returns SSH host key signers for the gateway.
//
// Three key types are persisted under os.UserConfigDir()/flyssh/ so that
// third-party clients don't see a host key change on every restart:
//
//   - ed25519            (modern OpenSSH, WinSCP ≥ 5.18, XShell ≥ 6)
//   - ecdsa-sha2-nistp256 (XShell 5/6, PuTTY < 0.68, most GUI clients)
//   - ssh-rsa            (legacy clients, fallback of last resort)
func loadOrGenerateHostKeys() ([]ssh.Signer, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("gateway host key: config dir: %w", err)
	}
	keyDir := filepath.Join(dir, "flyssh")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("gateway host key: mkdir: %w", err)
	}

	type keySpec struct {
		file    string
		genFunc func() (crypto.Signer, error)
	}
	specs := []keySpec{
		{
			file: "gateway_host_key",
			genFunc: func() (crypto.Signer, error) {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				return priv, err
			},
		},
		{
			file: "gateway_host_key_ecdsa",
			genFunc: func() (crypto.Signer, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			},
		},
		{
			file: "gateway_host_key_rsa",
			genFunc: func() (crypto.Signer, error) {
				return rsa.GenerateKey(rand.Reader, 3072)
			},
		},
	}

	signers := make([]ssh.Signer, 0, len(specs))
	for _, spec := range specs {
		signer, err := loadOrGenerateOneKey(keyDir, spec.file, spec.genFunc)
		if err != nil {
			return nil, err
		}
		signers = append(signers, signer)
	}
	return signers, nil
}

// loadOrGenerateOneKey loads a persisted private key or generates and saves a
// new one using genFunc.
func loadOrGenerateOneKey(keyDir, name string, genFunc func() (crypto.Signer, error)) (ssh.Signer, error) {
	keyPath := filepath.Join(keyDir, name)

	if data, err := os.ReadFile(keyPath); err == nil {
		if signer, err := ssh.ParsePrivateKey(data); err == nil {
			return signer, nil
		}
		// Corrupted key — regenerate below.
	}

	priv, err := genFunc()
	if err != nil {
		return nil, fmt.Errorf("gateway host key %s: generate: %w", name, err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("gateway host key %s: marshal: %w", name, err)
	}
	pemData := pem.EncodeToMemory(pemBlock)

	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		return nil, fmt.Errorf("gateway host key %s: write: %w", name, err)
	}

	signer, err := ssh.ParsePrivateKey(pemData)
	if err != nil {
		return nil, fmt.Errorf("gateway host key %s: parse generated: %w", name, err)
	}
	return signer, nil
}
