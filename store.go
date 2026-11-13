package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Settings are global options edited on the Settings page.
type Settings struct {
	Email        string `json:"email"`
	Staging      bool   `json:"staging"`
	CFToken      string `json:"cfToken,omitempty"`   // legacy (before DNS accounts), moved to DNSAccounts on start
	KeyType      string `json:"keyType"`             // rsa2048 | rsa4096 | ec256 | ec384
	RenewDays    int    `json:"renewDays"`           // renew when fewer days left
	CheckHours   int    `json:"checkHours"`          // scheduler interval
	DNSResolvers string `json:"dnsResolvers"`        // optional, comma separated, used for propagation checks
	AdminHash    string `json:"adminHash,omitempty"` // legacy (pre user accounts), migrated on start
	Require2FA   bool   `json:"require2faAll"`       // 2FA for every user (admins always need it)
}

// MailSettings configures SMTP, notifications and the public URL used in e-mailed links.
type MailSettings struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Security  string `json:"security"` // starttls | tls | none
	User      string `json:"user"`
	Password  string `json:"password,omitempty"`
	From      string `json:"from"`
	PublicURL string `json:"publicUrl"` // e.g. https://certs.example.com (used in invite/reset links)

	NotifyIssueOK    bool   `json:"notifyIssueOk"`
	NotifyIssueFail  bool   `json:"notifyIssueFail"`
	NotifyDeployOK   bool   `json:"notifyDeployOk"`
	NotifyDeployFail bool   `json:"notifyDeployFail"`
	NotifyExpiry     bool   `json:"notifyExpiry"`
	WarnDays         int    `json:"warnDays"` // expiry warning threshold
	ExtraRecipients  string `json:"extraRecipients"`
}

func (m MailSettings) configured() bool { return m.Host != "" && m.From != "" }

// Token is a one-time e-mailed link: an invitation or a password reset. Only the hash is stored.
type Token struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"` // invite | reset
	Hash      string    `json:"hash"`
	Email     string    `json:"email"`
	Role      string    `json:"role,omitempty"`   // invite
	UserID    string    `json:"userId,omitempty"` // reset
	CreatedBy string    `json:"createdBy,omitempty"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
}

// DNSAccount is a set of DNS credentials used for DNS-01 validation, e.g. one Cloudflare API token.
// Several accounts let certificates use different tokens per zone (or per Cloudflare account).
type DNSAccount struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Provider     string            `json:"provider"`          // cloudflare | rfc2136 | acmedns (see dnsProviders)
	Token        string            `json:"token,omitempty"`   // Cloudflare API token, sealed
	Config       map[string]string `json:"config,omitempty"`  // other providers: settings that aren't secret
	Secret       string            `json:"secret,omitempty"`  // other providers: secret settings as JSON, sealed
	ACMEDNS      []*acmeDNSReg     `json:"acmeDns,omitempty"` // acme-dns: one registration per certificate name
	Zones        []string          `json:"zones"`             // zones this account validates: from Cloudflare, or typed in
	ZonesChecked time.Time         `json:"zonesChecked,omitzero"`
	LastError    string            `json:"lastError,omitempty"`
}

// Cert is one ACME certificate (may contain several names / a wildcard).
type Cert struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	DNSID   string   `json:"dnsAccountId,omitempty"` // "" = pick the DNS account by domain

	// status, maintained by the app
	Fingerprint string    `json:"fingerprint,omitempty"`
	NotAfter    time.Time `json:"notAfter,omitzero"`
	LastAttempt time.Time `json:"lastAttempt,omitzero"`
	LastError   string    `json:"lastError,omitempty"`
}

// Router is an enrolled RouterOS device. After enrollment the app talks to it only via
// api-ssl with a dedicated, restricted service account. Admin SSH credentials used for
// enrollment are never stored.
type Router struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`

	// API access (set by enrollment)
	APIPort     int       `json:"apiPort"`
	ServiceUser string    `json:"serviceUser"`
	Secret      string    `json:"secret,omitempty"` // service account password, AES-GCM sealed
	Pins        []string  `json:"pins"`             // accepted api-ssl certificate SHA-256 fingerprints
	AllowedFrom string    `json:"allowedFrom"`      // address restriction on the service account
	SSHPort     int       `json:"sshPort"`          // used for (re-)enrollment only
	SSHHostKey  string    `json:"sshHostKey"`       // SSH host key confirmed at enrollment
	Identity    string    `json:"identity"`
	Board       string    `json:"board"`
	EnrolledAt  time.Time `json:"enrolledAt,omitzero"`
	EnrolledBy  string    `json:"enrolledBy"`
	RotatedAt   time.Time `json:"rotatedAt,omitzero"`      // last service password rotation
	Pending     string    `json:"pendingSecret,omitempty"` // new password during a rotation (crash safety)

	// what to deploy
	CertID    string   `json:"certId"`
	Services  []string `json:"services"`      // ip services, e.g. www-ssl, api-ssl
	ExtraCmds string   `json:"extraCommands"` // RouterOS script lines, {{cert}} is replaced

	// status
	DeployedFP string    `json:"deployedFingerprint,omitempty"`
	LastDeploy time.Time `json:"lastDeploy,omitzero"`
	LastSeen   time.Time `json:"lastSeen,omitzero"`
	LastError  string    `json:"lastError,omitempty"`
	Version    string    `json:"version,omitempty"`

	// legacy (SSH-password mode before enrollment existed) – wiped on load
	LegacyPassword string `json:"password,omitempty"`
	LegacyKey      string `json:"privateKey,omitempty"`
}

func (r *Router) enrolled() bool { return r.ServiceUser != "" && r.Secret != "" && len(r.Pins) > 0 }

// User is a web UI account.
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"` // admin | viewer
	Hash     string `json:"hash"` // bcrypt
	Email    string `json:"email,omitempty"`
	Notify   bool   `json:"notify"` // receive notification e-mails

	// two-factor authentication (TOTP)
	TOTPSecret   string   `json:"totpSecret,omitempty"`   // sealed; set = 2FA on
	TOTPPending  string   `json:"totpPending,omitempty"`  // sealed; during setup, until confirmed
	TOTPLastStep int64    `json:"totpLastStep,omitempty"` // last accepted time step (no code reuse)
	Recovery     []string `json:"recovery,omitempty"`     // SHA-256 of unused recovery codes

	// passkeys (optional, on top of TOTP)
	WebAuthnID []byte     `json:"webauthnId,omitempty"` // random user handle
	Passkeys   []*Passkey `json:"passkeys,omitempty"`
	Created    time.Time  `json:"created"`
	LastLogin  time.Time  `json:"lastLogin,omitzero"`
}

type Config struct {
	Settings Settings      `json:"settings"`
	Certs    []*Cert       `json:"certs"`
	Routers  []*Router     `json:"routers"`
	Users    []*User       `json:"users"`
	Mail     MailSettings  `json:"mail"`
	DNS      []*DNSAccount `json:"dnsAccounts"`
	Tokens   []*Token      `json:"tokens"`
}

// pruneTokens drops expired tokens.
func (c *Config) pruneTokens() {
	now, out := time.Now(), c.Tokens[:0]
	for _, t := range c.Tokens {
		if now.Before(t.Expires) {
			out = append(out, t)
		}
	}
	c.Tokens = out
}

func (c Config) dnsAccount(id string) *DNSAccount {
	for _, x := range c.DNS {
		if x.ID == id {
			return x
		}
	}
	return nil
}

func (c Config) user(id string) *User {
	for _, x := range c.Users {
		if x.ID == id {
			return x
		}
	}
	return nil
}

func (c Config) userByName(name string) *User {
	for _, x := range c.Users {
		if strings.EqualFold(x.Username, name) {
			return x
		}
	}
	return nil
}

func (u *User) has2FA() bool { return u.TOTPSecret != "" }

// needs2FA: admins always, everyone when the setting requires it.
func (u *User) needs2FA(c Config) bool { return u.Role == RoleAdmin || c.Settings.Require2FA }

func (c Config) adminCount() int {
	n := 0
	for _, x := range c.Users {
		if x.Role == RoleAdmin {
			n++
		}
	}
	return n
}

func (c Config) cert(id string) *Cert {
	for _, x := range c.Certs {
		if x.ID == id {
			return x
		}
	}
	return nil
}

func (c Config) router(id string) *Router {
	for _, x := range c.Routers {
		if x.ID == id {
			return x
		}
	}
	return nil
}

// Store persists Config as a single JSON file (written atomically, mode 0600).
type Store struct {
	mu   sync.RWMutex
	path string
	cfg  Config
}

func OpenStore(dir string) (*Store, error) {
	s := &Store{path: filepath.Join(dir, "config.json")}
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, &s.cfg); err != nil {
			return nil, err
		}
	}
	st := &s.cfg.Settings
	if st.KeyType == "" {
		st.KeyType = "rsa2048"
	}
	if st.RenewDays <= 0 {
		st.RenewDays = 30
	}
	if st.CheckHours <= 0 {
		st.CheckHours = 12
	}
	for _, r := range s.cfg.Routers {
		if r.LegacyPassword != "" || r.LegacyKey != "" {
			r.LegacyPassword, r.LegacyKey = "", ""
			r.LastError = "stored SSH credentials were removed for security – enroll this device"
		}
	}
	if m := &s.cfg.Mail; m.WarnDays == 0 { // never configured: sensible defaults
		*m = MailSettings{Port: 587, Security: "starttls", WarnDays: 14,
			NotifyIssueOK: true, NotifyIssueFail: true, NotifyDeployFail: true, NotifyExpiry: true}
	}
	return s, s.save()
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(&s.cfg, "", "  ")
	if err != nil {
		return err
	}
	return writeFileSync(s.path, b, 0o600)
}

// writeFileSync writes a file so that a power cut leaves either the old or the new
// content: write to a temporary file, flush it to disk, rename it into place, and
// flush the directory so the rename itself is durable.
func writeFileSync(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// Snapshot returns a deep copy of the config.
func (s *Store) Snapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, _ := json.Marshal(&s.cfg)
	var c Config
	_ = json.Unmarshal(b, &c)
	return c
}

// SealSecrets encrypts the Cloudflare token and SMTP password if they are still stored
// in plain text (configs written by versions before 1.1). It returns how many it converted.
func (s *Store) SealSecrets(sl *sealer) (int, error) {
	n := 0
	err := s.Update(func(c *Config) error {
		ps := []*string{&c.Settings.CFToken, &c.Mail.Password}
		for _, a := range c.DNS {
			ps = append(ps, &a.Token)
		}
		for _, p := range ps {
			if *p != "" && !isSealed(*p) {
				*p = sl.seal(*p)
				n++
			}
		}
		return nil
	})
	return n, err
}

// Read gives fn read-only access to the live config (no copy). fn must not keep references.
func (s *Store) Read(fn func(*Config)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn(&s.cfg)
}

// Update mutates the config under lock and persists it if fn returns nil.
func (s *Store) Update(fn func(*Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.cfg); err != nil {
		return err
	}
	return s.save()
}

func newID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
