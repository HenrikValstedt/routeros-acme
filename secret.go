package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Device service-account secrets are stored encrypted (AES-256-GCM). The key comes
// from SECRET_KEY or is generated once into <data>/secret.key (mode 0600). This
// protects config.json in backups/copies; keep secret.key out of those backups.
type sealer struct{ aead cipher.AEAD }

func loadSealer(dataDir string) (*sealer, error) {
	var key []byte
	if s := os.Getenv("SECRET_KEY"); s != "" {
		h := sha256.Sum256([]byte(s))
		key = h[:]
	} else {
		path := filepath.Join(dataDir, "secret.key")
		b, err := os.ReadFile(path)
		switch {
		case err == nil && len(b) == 32:
			key = b
		case err == nil || errors.Is(err, os.ErrNotExist):
			if err == nil {
				return nil, errors.New("secret.key has an unexpected size")
			}
			key = make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return nil, err
			}
			if err := os.WriteFile(path, key, 0o600); err != nil {
				return nil, err
			}
		default:
			return nil, err
		}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sealer{aead}, nil
}

func (s *sealer) seal(plain string) string {
	nonce := make([]byte, s.aead.NonceSize())
	_, _ = rand.Read(nonce)
	return "v1:" + base64.RawStdEncoding.EncodeToString(s.aead.Seal(nonce, nonce, []byte(plain), []byte("routeros-acme")))
}

func isSealed(v string) bool { return strings.HasPrefix(v, "v1:") }

// reveal returns a stored secret in plain form: "" stays "", and a value written
// before it was encrypted is returned as is.
func (s *sealer) reveal(v string) (string, error) {
	if v == "" || !isSealed(v) {
		return v, nil
	}
	return s.open(v)
}

func (s *sealer) open(sealed string) (string, error) {
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(sealed, "v1:"))
	if err != nil || !strings.HasPrefix(sealed, "v1:") || len(b) < s.aead.NonceSize() {
		return "", errors.New("a stored secret is malformed")
	}
	n := s.aead.NonceSize()
	p, err := s.aead.Open(nil, b[:n], b[n:], []byte("routeros-acme"))
	if err != nil {
		return "", errors.New("cannot decrypt a stored secret (was secret.key or SECRET_KEY changed?)")
	}
	return string(p), nil
}
