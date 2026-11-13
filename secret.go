package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Stored secrets (device service passwords, DNS tokens, the SMTP password, 2FA
// secrets) are encrypted with AES-256-GCM. The key comes from, in this order:
//
//   - SECRET_KEY_FILE: a file outside the data folder, e.g. a Docker secret (hardened setup)
//   - SECRET_KEY: a passphrase in an environment variable
//   - <data>/secret.key: generated on first start (the default, zero setup)
//
// Switching from the data-folder key to SECRET_KEY_FILE or SECRET_KEY re-encrypts
// everything with the new key and then deletes <data>/secret.key.
type sealer struct{ aead cipher.AEAD }

const (
	keySourceData = "data folder"
	keySourceFile = "SECRET_KEY_FILE"
	keySourceEnv  = "SECRET_KEY"
)

// keyConfig is the key given from outside the data folder (nil = use <data>/secret.key).
// It is read before the process drops root, because a Docker secret may be readable by root only.
type keyConfig struct {
	key    []byte
	source string
}

func readKeyConfig() (keyConfig, error) {
	file, env := os.Getenv("SECRET_KEY_FILE"), os.Getenv("SECRET_KEY")
	switch {
	case file != "" && env != "":
		return keyConfig{}, errors.New("set SECRET_KEY_FILE or SECRET_KEY, not both")
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return keyConfig{}, fmt.Errorf("SECRET_KEY_FILE: %w", err)
		}
		k, err := keyFromFile(b)
		if err != nil {
			return keyConfig{}, fmt.Errorf("SECRET_KEY_FILE %s: %w", file, err)
		}
		return keyConfig{k, keySourceFile}, nil
	case env != "":
		h := sha256.Sum256([]byte(env))
		return keyConfig{h[:], keySourceEnv}, nil
	}
	return keyConfig{source: keySourceData}, nil
}

// keyFromFile reads a key file: exactly 32 bytes are used as is (that is what the app
// generates as secret.key); anything else is a text passphrase, without surrounding
// whitespace. The same rule applies to secret.key and SECRET_KEY_FILE, so a key file
// can be moved between the two in either direction.
func keyFromFile(b []byte) ([]byte, error) {
	if len(b) == 32 {
		return bytes.Clone(b), nil
	}
	t := strings.TrimSpace(string(b))
	if !utf8.ValidString(t) || strings.ContainsFunc(t, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return nil, errors.New("must hold exactly 32 random bytes or a text passphrase")
	}
	if utf8.RuneCountInString(t) < 16 {
		return nil, errors.New("the passphrase is too short (use at least 16 characters, e.g. from: openssl rand -base64 32)")
	}
	h := sha256.Sum256([]byte(t))
	return h[:], nil
}

func newSealer(key []byte) (*sealer, error) {
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

// loadSealer is the simple form used by tests: SECRET_KEY or <data>/secret.key.
func loadSealer(dataDir string) (*sealer, error) {
	kc := keyConfig{source: keySourceData}
	if s := os.Getenv("SECRET_KEY"); s != "" {
		h := sha256.Sum256([]byte(s))
		kc = keyConfig{h[:], keySourceEnv}
	}
	sl, _, err := openSealer(nil, dataDir, kc, false)
	return sl, err
}

// keyReport says what openSealer found and did; it is logged and shown to admins.
type keyReport struct {
	Source      string // keySource*
	Reencrypted int    // secrets moved from the data-folder key to the external key
	RemovedKey  bool   // <data>/secret.key was deleted after the move
	Forgotten   []string
}

// openSealer picks the key and checks it against every stored secret. When st is nil
// (tests), nothing is checked. With forget, secrets that can't be decrypted are
// removed instead of stopping with an error (-forget-secrets, after a lost key).
func openSealer(st *Store, dataDir string, kc keyConfig, forget bool) (*sealer, keyReport, error) {
	rep := keyReport{Source: kc.source}
	path := filepath.Join(dataDir, "secret.key")
	var dataKey []byte
	switch b, err := os.ReadFile(path); {
	case err == nil:
		if dataKey, err = keyFromFile(b); err != nil {
			return nil, rep, fmt.Errorf("%s: %w", path, err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, rep, err
	}

	var sealed []string
	if st != nil {
		st.Read(func(c *Config) {
			for _, f := range sealedFields(c) {
				if isSealed(*f.p) {
					sealed = append(sealed, *f.p)
				}
			}
		})
	}

	active := kc.key
	if active == nil {
		active = dataKey
	}
	if active == nil {
		if len(sealed) > 0 && !forget {
			return nil, rep, errors.New("secret.key is missing from the data folder, but stored secrets are encrypted. " +
				"If you used SECRET_KEY_FILE, set it again; to go back to the default, copy that key file into the data folder as secret.key. " +
				"If the key is lost for good, see -forget-secrets in the README")
		}
		active = make([]byte, 32)
		if _, err := rand.Read(active); err != nil {
			return nil, rep, err
		}
		if err := writeFileSync(path, active, 0o600); err != nil {
			return nil, rep, err
		}
		dataKey = active
	}
	act, err := newSealer(active)
	if err != nil {
		return nil, rep, err
	}
	var old *sealer // the data-folder key, while moving to an external key
	if kc.key != nil && dataKey != nil && !bytes.Equal(kc.key, dataKey) {
		if old, err = newSealer(dataKey); err != nil {
			return nil, rep, err
		}
	}

	bad := 0
	for _, v := range sealed {
		if _, err := act.open(v); err == nil {
			continue
		}
		if old != nil {
			if _, err := old.open(v); err == nil {
				rep.Reencrypted++
				continue
			}
		}
		bad++
	}
	if bad > 0 && !forget {
		return nil, rep, fmt.Errorf("%d of %d stored secrets can't be decrypted with the key from the %s. %s "+
			"If the key is lost for good, see -forget-secrets in the README", bad, len(sealed), kc.source, keyHint(kc.source))
	}

	if rep.Reencrypted > 0 || bad > 0 {
		err := st.Update(func(c *Config) error {
			for _, f := range sealedFields(c) {
				if !isSealed(*f.p) {
					continue
				}
				if _, err := act.open(*f.p); err == nil {
					continue
				}
				if old != nil {
					if p, err := old.open(*f.p); err == nil {
						*f.p = act.seal(p)
						continue
					}
				}
				*f.p = "" // forget: can't be decrypted
				if f.clear != nil {
					f.clear()
				}
				rep.Forgotten = append(rep.Forgotten, f.what)
			}
			return nil
		})
		if err != nil {
			return nil, rep, err
		}
	}
	// The secrets now open with the external key: the key in the data folder is
	// no longer needed, and keeping it next to config.json is what this avoids.
	if st != nil && kc.key != nil && dataKey != nil {
		if err := os.Remove(path); err != nil {
			return nil, rep, fmt.Errorf("removing %s: %w", path, err)
		}
		rep.RemovedKey = true
	}
	return act, rep, nil
}

func keyHint(source string) string {
	switch source {
	case keySourceFile:
		return "Point SECRET_KEY_FILE at the key file they were encrypted with."
	case keySourceEnv:
		return "Set SECRET_KEY to the value they were encrypted with."
	}
	return "If they were encrypted with a key from SECRET_KEY_FILE, set it again, or copy that key file over secret.key in the data folder."
}

// sealedField is one encrypted value in the config. clear undoes what depends on it
// when it has to be forgotten.
type sealedField struct {
	p     *string
	what  string
	clear func()
}

// sealedFields lists every encrypted value in the config. Keep it complete: values
// missing here are not re-encrypted when the key changes.
func sealedFields(c *Config) []sealedField {
	fs := []sealedField{
		{p: &c.Settings.CFToken, what: "Cloudflare token (legacy)"},
		{p: &c.Mail.Password, what: "SMTP password"},
	}
	for _, a := range c.DNS {
		fs = append(fs, sealedField{p: &a.Token, what: fmt.Sprintf("DNS account %q token", a.Name)},
			sealedField{p: &a.Secret, what: fmt.Sprintf("DNS account %q credentials", a.Name)})
		for _, r := range a.ACMEDNS {
			fs = append(fs, sealedField{p: &r.Password, what: fmt.Sprintf("DNS account %q: acme-dns registration of %s (its CNAME record changes)", a.Name, r.Name)})
		}
	}
	for _, r := range c.Routers {
		fs = append(fs,
			sealedField{p: &r.Secret, what: fmt.Sprintf("device %q service password (enroll it again)", r.Name),
				clear: func() {
					r.LastError = "the stored service password was lost with the encryption key – enroll this device again"
				}},
			sealedField{p: &r.Pending, what: fmt.Sprintf("device %q pending password", r.Name)})
	}
	for _, u := range c.Users {
		fs = append(fs,
			sealedField{p: &u.TOTPSecret, what: fmt.Sprintf("2FA of user %q (set up again at the next sign-in)", u.Username),
				clear: func() { u.TOTPLastStep, u.Recovery = 0, nil; clearPasskeys(u) }},
			sealedField{p: &u.TOTPPending, what: fmt.Sprintf("2FA setup in progress of user %q", u.Username)})
	}
	return fs
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
		return "", errors.New("cannot decrypt a stored secret (was the encryption key changed?)")
	}
	return string(p), nil
}
