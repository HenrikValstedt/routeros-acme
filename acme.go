package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type acmeUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	KeyPEM       string                 `json:"key"`
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

var keyTypes = map[string]certcrypto.KeyType{
	"rsa2048": certcrypto.RSA2048,
	"rsa4096": certcrypto.RSA4096,
	"ec256":   certcrypto.EC256,
	"ec384":   certcrypto.EC384,
}

// loadAccount loads (or creates) the ACME account key for email+CA.
func loadAccount(dataDir, email string, staging bool) (*acmeUser, string, error) {
	ca := "production"
	if staging {
		ca = "staging"
	}
	path := filepath.Join(dataDir, "accounts", ca, sanitize(email)+".json")
	u := &acmeUser{Email: email}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, u); err != nil {
			return nil, "", err
		}
		blk, _ := pem.Decode([]byte(u.KeyPEM))
		if blk == nil {
			return nil, "", errors.New("account key: bad PEM")
		}
		k, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return nil, "", err
		}
		u.key = k
		return u, path, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	der, _ := x509.MarshalECPrivateKey(k)
	u.key = k
	u.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	return u, path, nil
}

func saveAccount(path string, u *acmeUser) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(u, "", "  ")
	return writeFileSync(path, b, 0o600)
}

// obtain requests a new certificate via DNS-01 on Cloudflare and stores it
// as <data>/certs/<id>/{fullchain,privkey}.pem.
func obtain(dataDir string, st Settings, c Cert, prov challenge.Provider, logf func(string, ...any)) (*x509.Certificate, error) {
	if st.Email == "" {
		return nil, errors.New("the ACME e-mail address must be set in Settings")
	}
	if len(c.Domains) == 0 {
		return nil, errors.New("certificate has no domains")
	}
	u, accPath, err := loadAccount(dataDir, st.Email, st.Staging)
	if err != nil {
		return nil, fmt.Errorf("account: %w", err)
	}

	cfg := lego.NewConfig(u)
	cfg.UserAgent = "routeros-acme"
	cfg.CADirURL = lego.LEDirectoryProduction
	if st.Staging {
		cfg.CADirURL = lego.LEDirectoryStaging
	}
	if u := os.Getenv("ACME_DIRECTORY_URL"); u != "" {
		cfg.CADirURL = u // testing only, e.g. a local Pebble server (its CA via LEGO_CA_CERTIFICATES)
	}
	kt, ok := keyTypes[st.KeyType]
	if !ok {
		kt = certcrypto.RSA2048
	}
	cfg.Certificate.KeyType = kt

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	var opts []dns01.ChallengeOption
	if r := splitList(st.DNSResolvers); len(r) > 0 {
		opts = append(opts, dns01.AddRecursiveNameservers(dns01.ParseNameservers(r)))
	}
	if err := client.Challenge.SetDNS01Provider(prov, opts...); err != nil {
		return nil, err
	}

	if u.Registration == nil {
		logf("registering ACME account for %s", st.Email)
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("register: %w", err)
		}
		u.Registration = reg
		if err := saveAccount(accPath, u); err != nil {
			return nil, err
		}
	}

	logf("requesting certificate %q for %s", c.Name, strings.Join(c.Domains, ", "))
	res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: c.Domains, Bundle: true})
	if err != nil {
		return nil, err
	}
	leaf, err := parseLeaf(res.Certificate)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(dataDir, "certs", c.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// the key first, then the chain: the chain's fingerprint is what deploys compare
	if err := writeFileSync(filepath.Join(dir, "privkey.pem"), res.PrivateKey, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileSync(filepath.Join(dir, "fullchain.pem"), res.Certificate, 0o600); err != nil {
		return nil, err
	}
	return leaf, nil
}

func loadCertFiles(dataDir, id string) (chain, key []byte, err error) {
	dir := filepath.Join(dataDir, "certs", id)
	if chain, err = os.ReadFile(filepath.Join(dir, "fullchain.pem")); err != nil {
		return nil, nil, err
	}
	key, err = os.ReadFile(filepath.Join(dir, "privkey.pem"))
	return chain, key, err
}

func parseLeaf(chain []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(chain)
	if blk == nil {
		return nil, errors.New("no PEM certificate found")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// fingerprint is the SHA-256 of the DER cert, hex lowercase — same format
// RouterOS shows in /certificate fingerprint.
func fingerprint(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return hex.EncodeToString(h[:])
}

func needsRenewal(c *Cert, renewDays int) bool {
	return c.NotAfter.IsZero() || time.Until(c.NotAfter) < time.Duration(renewDays)*24*time.Hour
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == ';' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}
