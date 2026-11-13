package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

// acme-dns (https://github.com/joohoi/acme-dns): each certificate name gets its own
// registration on the acme-dns server, and the user creates one CNAME record once:
//
//	_acme-challenge.router.example.com  CNAME  <uuid>.acme-dns.example.com
//
// Let's Encrypt follows the CNAME, and the app only ever talks to the acme-dns server.
type acmeDNSReg struct {
	Name       string    `json:"name"`       // certificate name without "*.", e.g. router.example.com
	FullDomain string    `json:"fulldomain"` // CNAME target
	Subdomain  string    `json:"subdomain"`
	Username   string    `json:"username"`
	Password   string    `json:"password"` // sealed
	CNAMEOK    bool      `json:"cnameOk"`
	Checked    time.Time `json:"checked,omitzero"`
}

func (r *acmeDNSReg) record() string { return "_acme-challenge." + r.Name }

var acmeDNSClient = &http.Client{Timeout: 20 * time.Second}

func acmeDNSPost(apiBase, path string, hdr map[string]string, body any) ([]byte, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", strings.TrimRight(apiBase, "/")+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := acmeDNSClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("acme-dns: %w", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("acme-dns %s: HTTP %d %s", path, resp.StatusCode, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func acmeDNSRegister(apiBase string) (*acmeDNSReg, string, error) {
	b, err := acmeDNSPost(apiBase, "/register", nil, map[string]any{})
	if err != nil {
		return nil, "", err
	}
	var r struct{ Username, Password, FullDomain, Subdomain string }
	if err := json.Unmarshal(b, &r); err != nil || r.Username == "" || r.FullDomain == "" {
		return nil, "", errors.New("acme-dns: unexpected answer to /register – is this an acme-dns server?")
	}
	return &acmeDNSReg{FullDomain: strings.ToLower(strings.TrimSuffix(r.FullDomain, ".")), Subdomain: r.Subdomain, Username: r.Username}, r.Password, nil
}

// acme-dns keeps the two newest values of a name and dates them to the second. A
// wildcard and its base name share one name, so two updates in the same second as an
// earlier one (e.g. a Test) could drop a challenge value. Updates to the same name are
// therefore spaced at least 1.1 s apart.
var (
	acmeDNSLastMu sync.Mutex
	acmeDNSLast   = map[string]time.Time{} // apiBase + subdomain -> last update
)

func acmeDNSUpdate(apiBase string, r *acmeDNSReg, password, value string) error {
	key := apiBase + "|" + r.Subdomain
	acmeDNSLastMu.Lock()
	if wait := time.Until(acmeDNSLast[key].Add(1100 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	_, err := acmeDNSPost(apiBase, "/update", map[string]string{"X-Api-User": r.Username, "X-Api-Key": password},
		map[string]string{"subdomain": r.Subdomain, "txt": value})
	acmeDNSLast[key] = time.Now()
	acmeDNSLastMu.Unlock()
	return err
}

// acmeDNSProvider is the lego DNS-01 provider for an acme-dns account.
type acmeDNSProvider struct {
	apiBase   string
	regs      map[string]*acmeDNSReg
	passwords map[string]string
}

func newACMEDNSProvider(a *DNSAccount, sl *sealer) (*acmeDNSProvider, error) {
	p := &acmeDNSProvider{apiBase: a.Config["apiBase"], regs: map[string]*acmeDNSReg{}, passwords: map[string]string{}}
	for _, r := range a.ACMEDNS {
		pw, err := sl.reveal(r.Password)
		if err != nil {
			return nil, err
		}
		p.regs[r.Name], p.passwords[r.Name] = r, pw
	}
	return p, nil
}

func (p *acmeDNSProvider) Present(domain, _, keyAuth string) error {
	r := p.regs[bareName(domain)]
	if r == nil {
		return fmt.Errorf("%s isn't registered with acme-dns yet", domain)
	}
	return acmeDNSUpdate(p.apiBase, r, p.passwords[r.Name], dns01.GetChallengeInfo(domain, keyAuth).Value)
}

// CleanUp has nothing to do: acme-dns keeps the two latest values and replaces them.
func (p *acmeDNSProvider) CleanUp(string, string, string) error { return nil }

func (p *acmeDNSProvider) Timeout() (time.Duration, time.Duration) {
	return 2 * time.Minute, 2 * time.Second
}

// namesFor lists the certificate names (without "*.") that an account validates.
func namesFor(cfg Config, accountID string) []string {
	var names []string
	for _, c := range cfg.Certs {
		routes, _ := routeCert(cfg, *c)
		for _, r := range routes {
			if n := bareName(r.Name); r.Account == accountID && !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}
	slices.Sort(names)
	return names
}

// acmeDNSMu serializes syncACMEDNS: a certificate save and a running check must not
// register the same name twice.
var acmeDNSMu sync.Mutex

// syncACMEDNS registers the names an acme-dns account validates and checks their CNAME records.
func (m *Manager) syncACMEDNS(id string) error {
	acmeDNSMu.Lock()
	defer acmeDNSMu.Unlock()
	cfg := m.store.Snapshot()
	a := cfg.dnsAccount(id)
	if a == nil || a.Provider != "acmedns" {
		return nil
	}
	have := map[string]*acmeDNSReg{}
	for _, r := range a.ACMEDNS {
		have[r.Name] = r
	}
	var added []*acmeDNSReg
	var firstErr error
	for _, n := range namesFor(cfg, id) {
		if have[n] != nil && have[n].Password != "" {
			continue // registered (a registration without password was lost with the encryption key: replace it)
		}
		r, pw, err := acmeDNSRegister(a.Config["apiBase"])
		if err != nil {
			firstErr = err
			break
		}
		// a first value right away: the acme-dns name then exists, so no resolver caches "no such name" for it
		placeholder := make([]byte, 32)
		_, _ = rand.Read(placeholder)
		if err := acmeDNSUpdate(a.Config["apiBase"], r, pw, base64.RawURLEncoding.EncodeToString(placeholder)); err != nil {
			firstErr = err
			break
		}
		r.Name, r.Password = n, m.sealer.seal(pw)
		added = append(added, r)
		m.logf("DNS account %q: registered %s with acme-dns – create CNAME %s → %s", a.Name, n, r.record(), r.FullDomain)
	}
	resolvers := splitList(cfg.Settings.DNSResolvers)
	nowReady := false
	defer func() {
		if nowReady { // a CNAME was just created: retry the waiting certificates right away
			m.Trigger()
		}
	}()
	return errors.Join(firstErr, m.store.Update(func(c *Config) error {
		x := c.dnsAccount(id)
		if x == nil {
			return nil
		}
		x.ACMEDNS = slices.DeleteFunc(x.ACMEDNS, func(r *acmeDNSReg) bool {
			return slices.ContainsFunc(added, func(n *acmeDNSReg) bool { return n.Name == r.Name })
		})
		x.ACMEDNS = append(x.ACMEDNS, added...)
		for _, r := range x.ACMEDNS {
			ok := cnamePointsTo(r.record(), r.FullDomain, resolvers)
			nowReady = nowReady || (ok && !r.CNAMEOK)
			r.CNAMEOK, r.Checked = ok, time.Now()
		}
		if nowReady {
			for _, cert := range c.Certs {
				if strings.HasPrefix(cert.LastError, cnameNeeded) {
					cert.LastError = "" // no back-off: it waited for the user, not for a failure
				}
			}
		}
		if firstErr != nil {
			x.LastError = firstErr.Error()
		} else {
			x.LastError = ""
		}
		return nil
	}))
}

// syncAllACMEDNS runs syncACMEDNS for every acme-dns account (after certificates or accounts change).
func (m *Manager) syncAllACMEDNS() {
	for _, a := range m.store.Snapshot().DNS {
		if a.Provider == "acmedns" {
			if err := m.syncACMEDNS(a.ID); err != nil {
				m.logf("DNS account %q: %v", a.Name, err)
			}
		}
	}
}

// cnameNeeded starts the error of a certificate that waits for its CNAME records.
const cnameNeeded = "create these CNAME records at your DNS host first"

// acmeDNSReady checks, before a certificate is requested, that every name routed to an
// acme-dns account is registered and has its CNAME. Otherwise Let's Encrypt would only
// fail the validation (and count it against the rate limits).
func (m *Manager) acmeDNSReady(c Cert) error {
	cfg := m.store.Snapshot()
	routes, err := routeCert(cfg, c)
	if err != nil {
		return nil // reported by dnsProviderFor
	}
	synced := map[string]bool{}
	var missing []string
	for _, r := range routes {
		a := cfg.dnsAccount(r.Account)
		if a == nil || a.Provider != "acmedns" {
			continue
		}
		if !synced[a.ID] {
			if err := m.syncACMEDNS(a.ID); err != nil {
				return fmt.Errorf("DNS account %q: %w", a.Name, err)
			}
			synced[a.ID] = true
		}
		for _, reg := range m.store.Snapshot().dnsAccount(a.ID).ACMEDNS {
			if reg.Name == bareName(r.Name) && !reg.CNAMEOK && !slices.Contains(missing, reg.record()+" → "+reg.FullDomain) {
				missing = append(missing, reg.record()+" → "+reg.FullDomain)
			}
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s: %s", cnameNeeded, strings.Join(missing, ", "))
	}
	return nil
}

// cnamePointsTo reports whether name is a CNAME for target. It asks the zone's
// authoritative name servers directly: a resolver may still remember "no such record"
// from a check before the user created it (for as long as the zone's negative TTL).
// It asks for the CNAME record itself, so nothing follows it to acme-dns: acme-dns
// answers "no such name" to anything but TXT, which resolvers would then cache.
func cnamePointsTo(name, target string, resolvers []string) bool {
	var servers []string
	if zone, err := dns01.FindZoneByFqdnCustom(dns.Fqdn(name), resolverAddrs(resolvers)); err == nil {
		servers = nameServers(strings.TrimSuffix(zone, "."), resolvers)
	}
	authoritative := len(servers) > 0
	if !authoritative {
		servers = resolverAddrs(resolvers) // fall back to the resolvers
	}
	c := &dns.Client{Timeout: 5 * time.Second}
	for _, s := range servers {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(name), dns.TypeCNAME)
		msg.RecursionDesired = !authoritative
		r, _, err := c.Exchange(msg, s)
		if err != nil {
			continue
		}
		for _, rr := range r.Answer {
			if cn, ok := rr.(*dns.CNAME); ok && strings.EqualFold(strings.TrimSuffix(cn.Target, "."), target) {
				return true
			}
		}
		return false // this server answered: no (or another) CNAME
	}
	return false
}

// resolverAddrs returns the resolvers from Settings, or the system's, as host:port.
func resolverAddrs(resolvers []string) []string {
	var out []string
	for _, r := range resolvers {
		out = append(out, withPort(r))
	}
	if len(out) == 0 {
		if cc, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil {
			for _, s := range cc.Servers {
				out = append(out, net.JoinHostPort(s, cc.Port))
			}
		}
	}
	return out
}

func (m *Manager) testACMEDNS(a *DNSAccount) dnsTestResult {
	if err := m.syncACMEDNS(a.ID); err != nil {
		return dnsTestResult{Message: err.Error()}
	}
	cfg := m.store.Snapshot()
	a = cfg.dnsAccount(a.ID)
	used := namesFor(cfg, a.ID)
	if len(used) == 0 {
		return dnsTestResult{Message: "No certificate uses this account yet. Add one whose names are in its zones, then test again."}
	}
	p, err := newACMEDNSProvider(a, m.sealer)
	if err != nil {
		return dnsTestResult{Message: err.Error()}
	}
	res, resolvers := dnsTestResult{OK: true}, splitList(cfg.Settings.DNSResolvers)
	for _, n := range used {
		r := p.regs[n]
		if r == nil {
			continue
		}
		if !r.CNAMEOK {
			res.OK = false
			res.Details = append(res.Details, fmt.Sprintf("✗ %s: create CNAME %s → %s", n, r.record(), r.FullDomain))
			continue
		}
		v := make([]byte, 32)
		_, _ = rand.Read(v)
		value := base64.RawURLEncoding.EncodeToString(v) // 43 characters, like a real challenge
		if err := acmeDNSUpdate(p.apiBase, r, p.passwords[n], value); err != nil {
			res.OK = false
			res.Details = append(res.Details, fmt.Sprintf("✗ %s: %v", n, err))
			continue
		}
		servers := nameServers(r.FullDomain[strings.Index(r.FullDomain, ".")+1:], resolvers)
		if len(servers) == 0 {
			res.Details = append(res.Details, fmt.Sprintf("✓ %s: CNAME found, record updated (couldn't look up the acme-dns name servers to double-check)", n))
			continue
		}
		if _, err := waitForTXT(r.FullDomain, value, servers, 20*time.Second); err != nil {
			res.OK = false
			res.Details = append(res.Details, fmt.Sprintf("✗ %s: CNAME found and record updated, but %v", n, err))
			continue
		}
		res.Details = append(res.Details, fmt.Sprintf("✓ %s: CNAME found, test record served by acme-dns", n))
	}
	if res.OK {
		res.Message = fmt.Sprintf("All %d name(s) are ready.", len(used))
		m.logf("DNS account %q: test OK (%s)", a.Name, strings.Join(used, ", "))
	} else {
		res.Message = "Some names aren't ready yet."
	}
	return res
}
