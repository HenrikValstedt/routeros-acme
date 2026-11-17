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
	mrand "math/rand/v2"
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

// newACMEClient builds a lego client for the configured CA. The account is loaded
// (or a key generated) but not registered.
func newACMEClient(dataDir string, st Settings) (*lego.Client, *acmeUser, string, error) {
	if st.Email == "" {
		return nil, nil, "", errors.New("the ACME e-mail address must be set in Settings")
	}
	u, accPath, err := loadAccount(dataDir, st.Email, st.Staging)
	if err != nil {
		return nil, nil, "", fmt.Errorf("account: %w", err)
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
		return nil, nil, "", err
	}
	return client, u, accPath, nil
}

// obtain requests a new certificate via DNS-01 and stores it as
// <data>/certs/<id>/{fullchain,privkey}.pem. replaces is the ARI certificate ID of the
// certificate this one renews ("" = a new certificate); it lets Let's Encrypt treat the
// order as a renewal (exempt from rate limits).
func obtain(dataDir string, st Settings, c Cert, prov challenge.Provider, replaces string, logf func(string, ...any)) (*x509.Certificate, error) {
	if len(c.Domains) == 0 {
		return nil, errors.New("certificate has no domains")
	}
	client, u, accPath, err := newACMEClient(dataDir, st)
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
	req := certificate.ObtainRequest{Domains: c.Domains, Bundle: true, ReplacesCertID: replaces}
	res, err := client.Certificate.Obtain(req)
	if err != nil && replaces != "" && strings.Contains(strings.ToLower(err.Error()), "replace") {
		// The CA refused the renewal link itself (lego already handles "alreadyReplaced"):
		// order a plain new certificate rather than failing the renewal.
		logf("certificate %q: the CA did not accept it as a renewal (%v) – requesting it as a new certificate", c.Name, err)
		req.ReplacesCertID = ""
		res, err = client.Certificate.Obtain(req)
	}
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

// renewalInfo asks the CA for the suggested renewal window of leaf (ACME Renewal
// Information, RFC 9773). It needs no registered account.
func renewalInfo(dataDir string, st Settings, leaf *x509.Certificate) (*certificate.RenewalInfoResponse, error) {
	client, _, _, err := newACMEClient(dataDir, st)
	if err != nil {
		return nil, err
	}
	ri, err := client.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: leaf})
	if err != nil {
		return nil, err
	}
	// lego doesn't check the HTTP status: an unknown certificate (another CA, staging vs
	// production) decodes as an empty window.
	w := ri.SuggestedWindow
	if w.Start.IsZero() || w.End.Before(w.Start) {
		return nil, errors.New("the CA has no renewal information for this certificate")
	}
	return ri, nil
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

// ariFloor: renew this close to expiry even if the CA's window says later (a safety net
// against a wrong or stale window).
const ariFloor = 7 * 24 * time.Hour

// hasARI reports whether c has a renewal time from the CA for its current certificate.
func (c *Cert) hasARI() bool {
	return !c.RenewAt.IsZero() && c.ARIFor != "" && c.ARIFor == c.Fingerprint
}

// renewTime is when c is due: the time picked in the CA's renewal window (ARI), or
// otherwise renewDays before expiry. Zero = not issued yet (due now).
func renewTime(c *Cert, renewDays int) time.Time {
	if c.NotAfter.IsZero() {
		return time.Time{}
	}
	fixed := c.NotAfter.Add(-time.Duration(renewDays) * 24 * time.Hour)
	if !c.hasARI() {
		return fixed
	}
	floor := c.NotAfter.Add(-min(ariFloor, time.Duration(renewDays)*24*time.Hour))
	if c.RenewAt.Before(floor) {
		return c.RenewAt
	}
	return floor
}

func needsRenewal(c *Cert, renewDays int, now time.Time) bool {
	return !now.Before(renewTime(c, renewDays))
}

// pickInWindow chooses a uniformly random time in [start, end), as RFC 9773 recommends,
// so that many clients don't renew at the same moment.
func pickInWindow(start, end time.Time) time.Time {
	if w := end.Sub(start); w > 0 {
		return start.Add(time.Duration(mrand.Int64N(int64(w))))
	}
	return start
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
