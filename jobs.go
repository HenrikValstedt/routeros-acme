package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type logLine struct {
	T   time.Time `json:"t"`
	Msg string    `json:"msg"`
}

// Manager runs certificate and deploy jobs one at a time.
type Manager struct {
	store   *Store
	dataDir string

	jobMu sync.Mutex // serialises jobs
	busy  atomic.Int32

	logMu sync.Mutex
	logs  []logLine

	wake chan struct{}

	// notifications
	evMu   sync.Mutex
	events []event
	sent   map[string]sentRecord
	mailer func(MailSettings, []string, string, string) error

	sealer *sealer // device secrets
}

func NewManager(s *Store, dataDir string) *Manager {
	return &Manager{store: s, dataDir: dataDir, wake: make(chan struct{}, 1), sent: map[string]sentRecord{}, mailer: sendMail}
}

func (m *Manager) logf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	log.Print(msg)
	m.logMu.Lock()
	m.logs = append(m.logs, logLine{time.Now(), msg})
	if len(m.logs) > 500 {
		m.logs = m.logs[len(m.logs)-500:]
	}
	m.logMu.Unlock()
}

func (m *Manager) Logs() []logLine {
	m.logMu.Lock()
	defer m.logMu.Unlock()
	return append([]logLine(nil), m.logs...)
}

func (m *Manager) Busy() bool { return m.busy.Load() > 0 }

// Go runs fn in the background, serialised with other jobs.
func (m *Manager) Go(fn func()) {
	m.busy.Add(1)
	go func() {
		defer m.busy.Add(-1)
		m.jobMu.Lock()
		defer m.jobMu.Unlock()
		fn()
		m.flushEvents()
	}()
}

// Scheduler periodically renews and deploys. Trigger() runs a check now.
func (m *Manager) Scheduler() {
	timer := time.NewTimer(20 * time.Second)
	for {
		select {
		case <-timer.C:
		case <-m.wake:
			timer.Stop()
		}
		m.Go(m.cycle)
		h := m.store.Snapshot().Settings.CheckHours
		timer.Reset(time.Duration(h) * time.Hour)
	}
}

func (m *Manager) Trigger() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// cycle renews certificates that are due and pushes them to routers that are out of date.
func (m *Manager) cycle() {
	cfg := m.store.Snapshot()
	m.logf("check: %d certificate(s), %d router(s)", len(cfg.Certs), len(cfg.Routers))
	for _, c := range cfg.Certs {
		if !needsRenewal(c, cfg.Settings.RenewDays) {
			continue
		}
		// Back off after a failure to stay clear of Let's Encrypt rate limits.
		if c.LastError != "" && time.Since(c.LastAttempt) < time.Hour {
			m.logf("certificate %q failed recently, retrying automatically after %s (or use Renew now)",
				c.Name, c.LastAttempt.Add(time.Hour).Format(time.TimeOnly))
			continue
		}
		m.issue(c.ID)
	}
	m.deployOutdated()
	m.rotateDue()
	m.checkExpiry()
	m.logf("check done")
}

// checkExpiry warns about certificates that are close to expiry (i.e. renewal keeps failing).
func (m *Manager) checkExpiry() {
	cfg := m.store.Snapshot()
	for _, c := range cfg.Certs {
		if c.NotAfter.IsZero() {
			continue
		}
		left := time.Until(c.NotAfter)
		if left < time.Duration(cfg.Mail.WarnDays)*24*time.Hour {
			days := int(left.Hours() / 24)
			text := fmt.Sprintf("%s (%s) expires in %d day(s) on %s", c.Name, strings.Join(c.Domains, ", "), days, c.NotAfter.Format(time.DateOnly))
			if left <= 0 {
				text = fmt.Sprintf("%s (%s) EXPIRED on %s", c.Name, strings.Join(c.Domains, ", "), c.NotAfter.Format(time.DateOnly))
			}
			if c.LastError != "" {
				text += " – last error: " + c.LastError
			}
			m.event(evExpiry, "cert:"+c.ID, text)
		}
	}
}

// deployOutdated pushes certificates to every enabled router that doesn't have the current one.
func (m *Manager) deployOutdated() {
	cfg := m.store.Snapshot()
	for _, r := range cfg.Routers {
		c := cfg.cert(r.CertID)
		if r.Enabled && r.enrolled() && c != nil && c.Fingerprint != "" && r.DeployedFP != c.Fingerprint {
			m.deploy(r.ID)
		}
	}
}

// issue obtains a certificate now (must run inside a job).
func (m *Manager) issue(id string) {
	cfg := m.store.Snapshot()
	c := cfg.cert(id)
	if c == nil {
		return
	}
	st := cfg.Settings
	var err error
	if m.sealer != nil {
		if st.CFToken, err = m.sealer.reveal(st.CFToken); err != nil { // decrypted only for this request
			err = fmt.Errorf("cloudflare token: %w – enter it again in Settings", err)
		}
	}
	var leaf *x509.Certificate
	if err == nil {
		leaf, err = obtain(m.dataDir, st, *c, m.logf)
	}
	_ = m.store.Update(func(cf *Config) error {
		x := cf.cert(id)
		if x == nil {
			return nil
		}
		x.LastAttempt = time.Now()
		if err != nil {
			x.LastError = err.Error()
			return nil
		}
		x.LastError = ""
		x.NotAfter = leaf.NotAfter
		x.Fingerprint = fingerprint(leaf)
		return nil
	})
	if err != nil {
		m.logf("certificate %q failed: %v", c.Name, err)
		m.event(evIssueFail, "cert:"+id, fmt.Sprintf("%s (%s): %v", c.Name, strings.Join(c.Domains, ", "), err))
		return
	}
	m.logf("certificate %q issued, valid until %s", c.Name, leaf.NotAfter.Format(time.DateOnly))
	m.event(evIssueOK, "cert:"+id, fmt.Sprintf("%s (%s), valid until %s", c.Name, strings.Join(c.Domains, ", "), leaf.NotAfter.Format(time.DateOnly)))
}

// session opens an api-ssl session to an enrolled device and finishes an
// interrupted password rotation if needed.
func (m *Manager) session(r *Router) (*apiClient, string, error) {
	c, pw, pending, err := connectDevice(*r, m.sealer)
	if err != nil {
		return nil, "", err
	}
	if pending {
		_ = m.store.Update(func(cf *Config) error {
			if x := cf.router(r.ID); x != nil {
				x.Secret, x.Pending, x.RotatedAt = x.Pending, "", time.Now()
			}
			return nil
		})
		m.logf("[%s] completed an interrupted password rotation", r.Name)
	}
	return c, pw, nil
}

// deploy pushes the device's certificate to it now (must run inside a job).
func (m *Manager) deploy(id string) {
	cfg := m.store.Snapshot()
	r := cfg.router(id)
	if r == nil {
		return
	}
	c := cfg.cert(r.CertID)
	var (
		version string
		err     error
	)
	switch {
	case !r.enrolled():
		err = fmt.Errorf("device is not enrolled")
	case c == nil:
		err = fmt.Errorf("no certificate selected")
	case c.Fingerprint == "":
		err = fmt.Errorf("certificate %q has not been issued yet", c.Name)
	default:
		var chain, key []byte
		if chain, key, err = loadCertFiles(m.dataDir, c.ID); err != nil {
			break
		}
		var api *apiClient
		if api, _, err = m.session(r); err != nil {
			break
		}
		m.logf("[%s] deploying %q to %s via api-ssl", r.Name, c.Name, r.Host)
		version = apiGet(api, "/system/resource", "version")
		err = deployAPI(api, *r, *c, chain, key, m.logf, func(fp string) error {
			// api-ssl is about to use the new certificate: accept it too. Keep the
			// enrollment pin and the previous one in case the switch doesn't happen.
			return m.store.Update(func(cf *Config) error {
				if x := cf.router(id); x != nil && len(x.Pins) > 0 {
					p := uniq(append(x.Pins, fp))
					if len(p) > 3 {
						p = append([]string{p[0]}, p[len(p)-2:]...)
					}
					x.Pins = p
				}
				return nil
			})
		})
		api.Close()
	}
	_ = m.store.Update(func(cf *Config) error {
		x := cf.router(id)
		if x == nil {
			return nil
		}
		if version != "" {
			x.Version, x.LastSeen = version, time.Now()
		}
		if err != nil {
			x.LastError = err.Error()
			return nil
		}
		x.LastError = ""
		x.LastDeploy = time.Now()
		x.DeployedFP = c.Fingerprint
		return nil
	})
	if err != nil {
		m.logf("[%s] deploy failed: %v", r.Name, err)
		m.event(evDeployFail, "router:"+id, fmt.Sprintf("%s (%s): %v", r.Name, r.Host, err))
		return
	}
	m.logf("[%s] deploy OK", r.Name)
	m.event(evDeployOK, "router:"+id, fmt.Sprintf("%s (%s) now uses %q", r.Name, r.Host, c.Name))
}

// test checks api-ssl connectivity and login right away.
func (m *Manager) test(id string) (map[string]string, error) {
	r := m.store.Snapshot().router(id)
	if r == nil {
		return nil, fmt.Errorf("not found")
	}
	api, _, err := m.session(r)
	if err != nil {
		m.logf("[%s] connection test failed: %v", r.Name, err)
		return nil, err
	}
	defer api.Close()
	info := map[string]string{
		"version":  apiGet(api, "/system/resource", "version"),
		"uptime":   apiGet(api, "/system/resource", "uptime"),
		"identity": apiGet(api, "/system/identity", "name"),
		"tls":      "pinned " + api.peerFP[:16] + "…",
	}
	_ = m.store.Update(func(cf *Config) error {
		if x := cf.router(id); x != nil {
			x.Version, x.Identity, x.LastSeen = info["version"], info["identity"], time.Now()
		}
		return nil
	})
	m.logf("[%s] api-ssl OK: RouterOS %s, identity %q, up %s", r.Name, info["version"], info["identity"], info["uptime"])
	return info, nil
}

// rotateDue rotates service-account passwords older than rotateEvery.
func (m *Manager) rotateDue() {
	for _, r := range m.store.Snapshot().Routers {
		if r.Enabled && r.enrolled() && time.Since(r.RotatedAt) > rotateEvery {
			if err := m.rotate(r.ID); err != nil {
				m.logf("[%s] password rotation failed: %v", r.Name, err)
			}
		}
	}
}

// rotate changes the service-account password on the device (must run inside a job).
func (m *Manager) rotate(id string) error {
	r := m.store.Snapshot().router(id)
	if r == nil {
		return fmt.Errorf("not found")
	}
	api, oldPw, err := m.session(r)
	if err != nil {
		return err
	}
	defer api.Close()
	newPw := randToken(32)
	// persist the new password first, so a crash mid-way can't lock us out
	if err := m.store.Update(func(cf *Config) error {
		if x := cf.router(id); x != nil {
			x.Pending = m.sealer.seal(newPw)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := rotatePassword(api, oldPw, newPw); err != nil {
		_ = m.store.Update(func(cf *Config) error {
			if x := cf.router(id); x != nil {
				x.Pending = ""
			}
			return nil
		})
		return err
	}
	_ = m.store.Update(func(cf *Config) error {
		if x := cf.router(id); x != nil {
			x.Secret, x.Pending, x.RotatedAt = x.Pending, "", time.Now()
		}
		return nil
	})
	m.logf("[%s] service account password rotated", r.Name)
	return nil
}
