package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/v4/challenge"
)

type logLine struct {
	T   time.Time `json:"t"`
	Msg string    `json:"msg"`
}

// Manager runs certificate and deploy jobs one at a time.
type Manager struct {
	store   *Store
	dataDir string

	jobMu    sync.Mutex // serialises jobs
	busy     atomic.Int32
	jobs     sync.WaitGroup
	stopping atomic.Bool // set by Shutdown: no new jobs, running ones stop between steps

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

// Go runs fn in the background, serialised with other jobs. After Shutdown it does nothing.
func (m *Manager) Go(fn func()) {
	if m.stopping.Load() {
		return
	}
	m.busy.Add(1)
	m.jobs.Add(1)
	go func() {
		defer m.jobs.Done()
		defer m.busy.Add(-1)
		m.jobMu.Lock()
		defer m.jobMu.Unlock()
		if m.stopping.Load() {
			return // queued behind another job when the stop came
		}
		fn()
		m.flushEvents()
	}()
}

// Shutdown stops new jobs and waits up to timeout for the running one, which finishes
// its current step (one certificate or one router) and skips the rest. It reports
// whether everything finished in time.
func (m *Manager) Shutdown(timeout time.Duration) bool {
	m.stopping.Store(true)
	done := make(chan struct{})
	go func() { m.jobs.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// stop tells a long job to end after its current step.
func (m *Manager) stop() bool { return m.stopping.Load() }

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
	m.refreshStaleZones()
	cfg := m.store.Snapshot()
	m.logf("check: %d certificate(s), %d router(s)", len(cfg.Certs), len(cfg.Routers))
	for _, c := range cfg.Certs {
		if m.stop() {
			m.logf("check stopped early: shutting down (the rest runs at the next start)")
			return
		}
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
		if m.stop() {
			return
		}
		c := cfg.cert(r.CertID)
		if r.Enabled && r.enrolled() && c != nil && c.Fingerprint != "" && (r.DeployedFP != c.Fingerprint || r.ChainFP != c.Fingerprint) {
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
	var leaf *x509.Certificate
	err := m.acmeDNSReady(*c) // acme-dns: registered and CNAMEs in place, before asking Let's Encrypt
	var prov challenge.Provider
	var routes []dnsRoute
	if err == nil {
		prov, routes, err = dnsProviderFor(m.store.Snapshot(), *c, m.sealer) // credentials decrypted only for this request
	}
	if err == nil {
		var via []string
		for _, r := range routes {
			if a := cfg.dnsAccount(r.Account); a != nil {
				via = append(via, r.Name+" → "+a.Name)
			}
		}
		m.logf("certificate %q: DNS validation via %s", c.Name, strings.Join(via, ", "))
		leaf, err = obtain(m.dataDir, cfg.Settings, *c, prov, m.logf)
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
	// Pins older than the certificate the router presents are no longer accepted.
	if slices.Index(r.Pins, c.peerFP) > 0 {
		pruned := false
		_ = m.store.Update(func(cf *Config) error {
			if x := cf.router(r.ID); x != nil {
				if p := prunePins(x.Pins, c.peerFP); len(p) < len(x.Pins) {
					x.Pins, pruned = p, true
				}
			}
			return nil
		})
		if pruned {
			m.logf("[%s] api-ssl certificate pin updated: older certificates are no longer accepted", r.Name)
		}
	}
	return c, pw, nil
}

// prunePins drops the pins older than the one the router presented. New fingerprints
// are always appended, so a pin a running deploy has just added (api-ssl not switched
// yet) is kept: a Test during a deploy must not cut the pin the router is about to use.
func prunePins(pins []string, presented string) []string {
	if i := slices.Index(pins, presented); i > 0 {
		return slices.Clone(pins[i:])
	}
	return pins
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
		if err == nil {
			err = checkServedChain(*r, *c, chain, m.logf)
		}
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
		x.DeployedFP, x.ChainFP = c.Fingerprint, c.Fingerprint
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
		if m.stop() {
			return
		}
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
