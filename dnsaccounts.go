package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
)

// cfAPI is Cloudflare's API base URL (CLOUDFLARE_API_URL overrides it, for tests).
var cfAPI = func() string {
	if v := os.Getenv("CLOUDFLARE_API_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "https://api.cloudflare.com/client/v4"
}()

// cloudflareZones lists the zones (domains) a token can see. It needs Zone:Read.
func cloudflareZones(token string) ([]string, error) {
	cl := &http.Client{Timeout: 20 * time.Second}
	var zones []string
	for page := 1; page <= 20; page++ {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/zones?per_page=50&page=%d", cfAPI, page), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := cl.Do(req)
		if err != nil {
			return nil, fmt.Errorf("cloudflare: %w", err)
		}
		var body struct {
			Success bool `json:"success"`
			Errors  []struct {
				Message string `json:"message"`
			} `json:"errors"`
			Result []struct {
				Name string `json:"name"`
			} `json:"result"`
			Info struct {
				TotalPages int `json:"total_pages"`
			} `json:"result_info"`
		}
		err = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("cloudflare: unexpected answer (HTTP %d)", resp.StatusCode)
		}
		if !body.Success {
			msg := fmt.Sprintf("HTTP %d", resp.StatusCode)
			if len(body.Errors) > 0 {
				msg = body.Errors[0].Message
			}
			return nil, fmt.Errorf("cloudflare rejected the token: %s", msg)
		}
		for _, z := range body.Result {
			zones = append(zones, strings.ToLower(z.Name))
		}
		if page >= body.Info.TotalPages {
			break
		}
	}
	sort.Strings(zones)
	return zones, nil
}

// zoneOf reports the most specific zone (longest suffix) of the accounts that covers name.
func zoneOf(name string, accounts []*DNSAccount) (*DNSAccount, string) {
	name = strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(name), "*."), ".")
	var best *DNSAccount
	bestZone := ""
	for _, a := range accounts {
		for _, z := range a.Zones {
			if (name == z || strings.HasSuffix(name, "."+z)) && len(z) > len(bestZone) {
				best, bestZone = a, z
			}
		}
	}
	return best, bestZone
}

// dnsRoute is the DNS account used for one name of a certificate.
type dnsRoute struct {
	Name    string `json:"name"`
	Account string `json:"accountId"`
	Zone    string `json:"zone"`
}

// routeCert decides which account validates each name of the certificate.
// With c.DNSID set, that account is used for every name.
func routeCert(cfg Config, c Cert) ([]dnsRoute, error) {
	if len(cfg.DNS) == 0 {
		return nil, errors.New("add a DNS account under Settings → DNS accounts first")
	}
	var routes []dnsRoute
	var missing []string
	for _, d := range c.Domains {
		if c.DNSID != "" {
			a := cfg.dnsAccount(c.DNSID)
			if a == nil {
				return nil, errors.New("the DNS account chosen for this certificate no longer exists")
			}
			_, z := zoneOf(d, []*DNSAccount{a})
			if z == "" && len(a.Zones) > 0 {
				missing = append(missing, d)
				continue
			}
			routes = append(routes, dnsRoute{d, a.ID, z})
			continue
		}
		a, z := zoneOf(d, cfg.DNS)
		if a == nil {
			// an account whose zones aren't known yet (lookup failed or still pending) is the fallback
			var unknown []*DNSAccount
			for _, x := range cfg.DNS {
				if len(x.Zones) == 0 {
					unknown = append(unknown, x)
				}
			}
			if len(unknown) == 1 {
				routes = append(routes, dnsRoute{d, unknown[0].ID, ""})
				continue
			}
			missing = append(missing, d)
			continue
		}
		routes = append(routes, dnsRoute{d, a.ID, z})
	}
	if len(missing) > 0 {
		who := "No DNS account"
		if c.DNSID != "" {
			who = fmt.Sprintf("DNS account %q", cfg.dnsAccount(c.DNSID).Name)
		}
		return routes, fmt.Errorf("%s covers %s – add a DNS account for that zone under Settings → DNS accounts",
			who, strings.Join(missing, ", "))
	}
	return routes, nil
}

// multiDNS sends each domain's DNS-01 challenge to the provider of its account.
type multiDNS struct {
	byName  map[string]challenge.Provider // "example.com" (wildcard prefix removed)
	timeout time.Duration
	poll    time.Duration
}

func bareName(d string) string { return strings.TrimPrefix(strings.ToLower(d), "*.") }

func (m *multiDNS) provider(domain string) (challenge.Provider, error) {
	if p, ok := m.byName[bareName(domain)]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("no DNS account for %s", domain)
}

func (m *multiDNS) Present(domain, token, keyAuth string) error {
	p, err := m.provider(domain)
	if err != nil {
		return err
	}
	return p.Present(domain, token, keyAuth)
}

func (m *multiDNS) CleanUp(domain, token, keyAuth string) error {
	p, err := m.provider(domain)
	if err != nil {
		return err
	}
	return p.CleanUp(domain, token, keyAuth)
}

func (m *multiDNS) Timeout() (time.Duration, time.Duration) { return m.timeout, m.poll }

// sequential is how a lego provider asks for its challenges to be solved one at a
// time (RFC 2136 replaces the whole TXT record set, so "*.example.com" and
// "example.com", which share _acme-challenge.example.com, can't be presented at once).
type sequential interface{ Sequential() time.Duration }

// seqMultiDNS is a multiDNS that passes that request on to lego.
type seqMultiDNS struct {
	*multiDNS
	interval time.Duration
}

func (s seqMultiDNS) Sequential() time.Duration { return s.interval }

// newCloudflare is replaceable in tests.
var newCloudflare = func(token string) (challenge.Provider, error) {
	cf := cloudflare.NewDefaultConfig()
	cf.AuthToken = token
	if os.Getenv("CLOUDFLARE_API_URL") != "" {
		cf.BaseURL = cfAPI
	}
	return cloudflare.NewDNSProviderConfig(cf)
}

// dnsProviderFor builds the DNS-01 provider for a certificate from its routes.
// Tokens are decrypted only here, for the duration of the request.
func dnsProviderFor(cfg Config, c Cert, sl *sealer) (challenge.Provider, []dnsRoute, error) {
	routes, err := routeCert(cfg, c)
	if err != nil {
		return nil, routes, err
	}
	m := &multiDNS{byName: map[string]challenge.Provider{}, timeout: 2 * time.Minute, poll: 2 * time.Second}
	perAccount := map[string]challenge.Provider{}
	for _, r := range routes {
		p, ok := perAccount[r.Account]
		if !ok {
			a := cfg.dnsAccount(r.Account)
			var err error
			if p, err = newProvider(a, sl); err != nil {
				return nil, routes, fmt.Errorf("DNS account %q: %w", a.Name, err)
			}
			perAccount[r.Account] = p
		}
		m.byName[bareName(r.Name)] = p
	}
	var seq time.Duration
	isSeq := false
	for _, p := range perAccount {
		if s, ok := p.(sequential); ok {
			isSeq, seq = true, max(seq, s.Sequential())
		}
	}
	if isSeq {
		return seqMultiDNS{m, seq}, routes, nil
	}
	return m, routes, nil
}

// migrateDNSAccounts turns the single Cloudflare token of earlier versions into the first DNS account.
func (s *Store) migrateDNSAccounts() (bool, error) {
	moved := false
	err := s.Update(func(c *Config) error {
		if c.Settings.CFToken == "" {
			return nil
		}
		if len(c.DNS) == 0 {
			c.DNS = append(c.DNS, &DNSAccount{ID: newID(), Name: "Cloudflare", Provider: "cloudflare", Token: c.Settings.CFToken})
			moved = true
		}
		c.Settings.CFToken = ""
		return nil
	})
	return moved, err
}

// refreshZones asks Cloudflare which zones an account's token can manage. For acme-dns
// it registers new certificate names and checks the CNAME records; zones of other
// providers are typed in, so there is nothing to refresh.
func (m *Manager) refreshZones(id string) error {
	a := m.store.Snapshot().dnsAccount(id)
	if a == nil {
		return errors.New("not found")
	}
	switch a.Provider {
	case "acmedns":
		return m.syncACMEDNS(id)
	case "cloudflare":
	default:
		return nil
	}
	tok, err := m.sealer.reveal(a.Token)
	var zones []string
	if err == nil {
		zones, err = cloudflareZones(tok)
	}
	_ = m.store.Update(func(c *Config) error {
		if x := c.dnsAccount(id); x != nil {
			x.ZonesChecked = time.Now()
			if err != nil {
				x.LastError = err.Error() // keep the last known zones
			} else {
				x.Zones, x.LastError = zones, ""
			}
		}
		return nil
	})
	if err != nil {
		m.logf("DNS account %q: zone lookup failed: %v", a.Name, err)
	}
	return err
}

// refreshStaleZones updates zone lists older than a day (run during checks and at start-up).
func (m *Manager) refreshStaleZones() {
	for _, a := range m.store.Snapshot().DNS {
		if a.Provider == "cloudflare" && time.Since(a.ZonesChecked) > 24*time.Hour {
			_ = m.refreshZones(a.ID)
		}
	}
}

// ---- API ----

type dnsAccountView struct {
	DNSAccount
	HasToken  bool        `json:"hasToken"`
	HasSecret bool        `json:"hasSecret"` // secret settings are stored (never sent)
	CNAMEs    []cnameView `json:"cnames,omitempty"`
}

type cnameView struct {
	Name   string `json:"name"`
	Record string `json:"record"`
	Target string `json:"target"`
	OK     bool   `json:"ok"`
}

func dnsViews(c Config) []dnsAccountView {
	out := []dnsAccountView{}
	for _, a := range c.DNS {
		v := dnsAccountView{DNSAccount: *a, HasToken: a.Token != "", HasSecret: a.Secret != ""}
		v.Token, v.Secret, v.ACMEDNS = "", "", nil
		if a.Provider == "acmedns" {
			used := namesFor(c, a.ID)
			for _, r := range a.ACMEDNS {
				if slices.Contains(used, r.Name) {
					v.CNAMEs = append(v.CNAMEs, cnameView{r.Name, r.record(), r.FullDomain, r.CNAMEOK})
				}
			}
		}
		out = append(out, v)
	}
	return out
}

// certRoutes tells the UI which account validates which name (or why none does).
func certRoutes(c Config) map[string]any {
	out := map[string]any{}
	for _, x := range c.Certs {
		routes, err := routeCert(c, *x)
		r := map[string]any{"routes": routes}
		if err != nil {
			r["error"] = err.Error()
		}
		out[x.ID] = r
	}
	return out
}

func (a *app) saveDNSAccount(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID       string            `json:"id"`
		Name     string            `json:"name"`
		Provider string            `json:"provider"`
		Token    string            `json:"token"` // Cloudflare (also accepted as secrets.token)
		Config   map[string]string `json:"config"`
		Secrets  map[string]string `json:"secrets"`
		Zones    []string          `json:"zones"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, err)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Provider == "" {
		in.Provider = "cloudflare"
	}
	def := providerByID(in.Provider)
	old := a.store.Snapshot().dnsAccount(in.ID)
	switch {
	case def == nil:
		fail(w, 400, fmt.Errorf("unknown DNS provider %q", in.Provider))
		return
	case in.ID != "" && old == nil:
		fail(w, 404, errors.New("not found"))
		return
	case old != nil && old.Provider != in.Provider:
		fail(w, 400, errors.New("the provider of an account can't change – add a new account instead"))
		return
	case len(in.Name) > 60:
		fail(w, 400, errors.New("name is too long"))
		return
	}
	// only the fields the provider defines
	cfg, sec := map[string]string{}, map[string]string{}
	if in.Secrets == nil {
		in.Secrets = map[string]string{}
	}
	if in.Token != "" {
		in.Secrets["token"] = in.Token
	}
	for _, f := range def.Fields {
		if f.Secret {
			if v := strings.TrimSpace(in.Secrets[f.Key]); v != "" {
				sec[f.Key] = v
			}
			continue
		}
		v := strings.TrimSpace(in.Config[f.Key])
		if v == "" {
			v = f.Default
		}
		if f.Required && v == "" {
			fail(w, 400, fmt.Errorf("%s is required", strings.ToLower(f.Label)))
			return
		}
		if v != "" {
			cfg[f.Key] = v
		}
	}
	hasSecret := func(k string) bool {
		if old == nil {
			return false
		}
		s, err := accountSecrets(old, a.mgr.sealer)
		return err == nil && s[k] != ""
	}
	for _, f := range def.Fields {
		if f.Secret && f.Required && sec[f.Key] == "" && !hasSecret(f.Key) {
			fail(w, 400, fmt.Errorf("%s is required", strings.ToLower(f.Label)))
			return
		}
	}
	if err := validateConfig(def.ID, cfg, sec, hasSecret); err != nil {
		fail(w, 400, err)
		return
	}
	var zones []string
	if !def.AutoZones {
		var err error
		if zones, err = normalizeZones(in.Zones); err != nil {
			fail(w, 400, err)
			return
		}
		if len(zones) == 0 {
			fail(w, 400, errors.New("enter at least one zone (domain) this account is for"))
			return
		}
	}
	// new credentials, or settings that change where they are used, need a fresh 2FA code
	changed := old == nil || len(sec) > 0 || (old != nil && !maps.Equal(old.Config, cfg) && !(len(old.Config) == 0 && len(cfg) == 0))
	if changed && !a.requireFresh(w, r) {
		return
	}
	if def.ID == "cloudflare" && sec["token"] != "" {
		// check the token with Cloudflare before saving it
		var err error
		if zones, err = cloudflareZones(sec["token"]); err != nil {
			fail(w, 400, fmt.Errorf("%v. The token needs Zone:Read and DNS:Edit", err))
			return
		}
		if len(zones) == 0 {
			fail(w, 400, errors.New("this token can't see any zones. Give it Zone:Read and DNS:Edit for at least one zone"))
			return
		}
	}
	var secretJSON string
	if def.ID != "cloudflare" && (len(sec) > 0 || old == nil) {
		merged := map[string]string{}
		if old != nil {
			if s, err := accountSecrets(old, a.mgr.sealer); err == nil {
				maps.Copy(merged, s)
			}
		}
		maps.Copy(merged, sec)
		if len(merged) > 0 {
			b, _ := json.Marshal(merged)
			secretJSON = a.mgr.sealer.seal(string(b))
		}
	}
	var saved DNSAccount
	err := a.store.Update(func(c *Config) error {
		x := c.dnsAccount(in.ID)
		if x == nil {
			x = &DNSAccount{ID: newID(), Provider: def.ID}
			c.DNS = append(c.DNS, x)
		}
		if in.Name == "" {
			in.Name = x.Name
		}
		if in.Name == "" && len(zones) > 0 {
			in.Name = zones[0]
		}
		x.Name = in.Name
		if def.ID == "cloudflare" {
			if sec["token"] != "" {
				x.Token, x.Zones, x.ZonesChecked, x.LastError = a.mgr.sealer.seal(sec["token"]), zones, time.Now(), ""
			}
		} else {
			if old != nil && old.Config["apiBase"] != cfg["apiBase"] {
				x.ACMEDNS = nil // another acme-dns server: register again
			}
			x.Config, x.Zones, x.LastError = cfg, zones, ""
			if secretJSON != "" {
				x.Secret = secretJSON
			}
		}
		saved = *x
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	for _, x := range a.store.Snapshot().Certs {
		if x.LastError != "" { // new credentials may fix a failed certificate: allow an immediate retry
			_ = a.store.Update(func(c *Config) error {
				if y := c.cert(x.ID); y != nil {
					y.LastError = ""
				}
				return nil
			})
		}
	}
	a.mgr.logf("DNS account %q (%s) saved by %s (zones: %s)", saved.Name, def.Name, currentUser(r).Username, strings.Join(saved.Zones, ", "))
	var warn string
	if def.ID == "acmedns" {
		if err := a.mgr.syncACMEDNS(saved.ID); err != nil {
			warn = err.Error()
		}
	}
	a.mgr.Trigger()
	writeJSON(w, map[string]any{"id": saved.ID, "zones": saved.Zones, "warning": warn})
}

func (a *app) testDNSAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if a.store.Snapshot().dnsAccount(id) == nil {
		fail(w, 404, errors.New("not found"))
		return
	}
	a.mgr.logf("DNS account test requested by %s", currentUser(r).Username)
	writeJSON(w, a.mgr.testAccount(id))
}

func (a *app) refreshDNSAccount(w http.ResponseWriter, r *http.Request) {
	if err := a.mgr.refreshZones(r.PathValue("id")); err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, a.store.Snapshot().dnsAccount(r.PathValue("id")).Zones)
}

func (a *app) deleteDNSAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var name string
	err := a.store.Update(func(c *Config) error {
		x := c.dnsAccount(id)
		if x == nil {
			return errors.New("not found")
		}
		for _, cert := range c.Certs {
			if cert.DNSID == id {
				return fmt.Errorf("certificate %q is set to use this account – change it first", cert.Name)
			}
		}
		name = x.Name
		out := c.DNS[:0]
		for _, y := range c.DNS {
			if y.ID != id {
				out = append(out, y)
			}
		}
		c.DNS = out
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.mgr.logf("DNS account %q deleted by %s", name, currentUser(r).Username)
	writeJSON(w, "ok")
}
