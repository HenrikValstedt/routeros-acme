package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns/rfc2136"
	"github.com/miekg/dns"
)

// DNS providers. Only providers that have been verified end to end are offered:
//
//   - cloudflare: API token; the zones are read from Cloudflare.
//   - rfc2136:    dynamic updates to your own DNS server (BIND, PowerDNS, Knot,
//     Technitium, Windows DNS, …), usually signed with a TSIG key.
//   - acmedns:    CNAME delegation to an acme-dns server. Works with any DNS host,
//     even without an API: one CNAME record per name, created once.
//
// The UI builds each provider's form from these definitions.
type providerField struct {
	Key         string   `json:"key"`
	Label       string   `json:"label"`
	Hint        string   `json:"hint,omitempty"`
	Placeholder string   `json:"placeholder,omitempty"`
	Secret      bool     `json:"secret,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Options     []string `json:"options,omitempty"`
	Default     string   `json:"default,omitempty"`
}

type providerDef struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Help      string          `json:"help"`      // HTML (static text from this file)
	AutoZones bool            `json:"autoZones"` // zones come from the provider, not typed in
	Fields    []providerField `json:"fields"`
}

var hostnameRE = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$`)

var tsigAlgorithms = []string{"hmac-sha256", "hmac-sha512", "hmac-sha384", "hmac-sha224", "hmac-sha1"}

var dnsProviders = []providerDef{
	{
		ID: "cloudflare", Name: "Cloudflare", AutoZones: true,
		Help: `In Cloudflare: <b>My Profile → API Tokens → Create Token</b>, use the <b>Edit zone DNS</b> template
(Zone:Read and DNS:Edit) and limit <b>Zone Resources</b> to the zones this token is for. The app checks the token and lists its zones when you save.`,
		Fields: []providerField{{Key: "token", Label: "API token", Secret: true, Required: true}},
	},
	{
		ID: "rfc2136", Name: "Own DNS server (RFC 2136)",
		Help: `For a DNS server you run yourself: BIND, PowerDNS, Knot, Technitium, Windows DNS and others. The app adds and removes
the <code>_acme-challenge</code> TXT records with dynamic updates. The server must be the <b>public, authoritative</b> server for the zones
(or their hidden primary), because Let's Encrypt checks the records from the internet. Allow updates for this TSIG key, ideally only for
<code>_acme-challenge</code> TXT records.`,
		Fields: []providerField{
			{Key: "nameserver", Label: "DNS server", Placeholder: "ns1.example.com or 192.0.2.53:53", Required: true,
				Hint: "Where updates are sent. Port 53 if none is given."},
			{Key: "tsigKey", Label: "TSIG key name", Placeholder: "acme-update", Hint: "Leave empty only if the server accepts unsigned updates from this address."},
			{Key: "tsigAlgorithm", Label: "TSIG algorithm", Options: tsigAlgorithms, Default: "hmac-sha256"},
			{Key: "tsigSecret", Label: "TSIG secret", Secret: true, Placeholder: "base64, from tsig-keygen or keymgr"},
		},
	},
	{
		ID: "acmedns", Name: "acme-dns (CNAME, any DNS host)",
		Help: `Works with <b>any DNS host</b>, also without an API. The app registers each certificate name with an
<a href="https://github.com/joohoi/acme-dns" target="_blank" rel="noopener">acme-dns</a> server and shows one CNAME record per name,
which you create once at your DNS host. After that, renewals need no access to your DNS at all.`,
		Fields: []providerField{
			{Key: "apiBase", Label: "acme-dns server", Placeholder: "https://acme-dns.example.com", Required: true,
				Hint: "Your own acme-dns server, or a public one such as https://auth.acme-dns.io. Opened in a browser it shows 404 Not Found: that's normal, it only answers the app."},
		},
	},
}

func providerByID(id string) *providerDef {
	for i := range dnsProviders {
		if dnsProviders[i].ID == id {
			return &dnsProviders[i]
		}
	}
	return nil
}

// accountSecrets returns the decrypted secret fields of an account.
func accountSecrets(a *DNSAccount, sl *sealer) (map[string]string, error) {
	out := map[string]string{}
	if a.Provider == "cloudflare" || a.Provider == "" {
		tok, err := sl.reveal(a.Token)
		out["token"] = tok
		return out, err
	}
	if a.Secret == "" {
		return out, nil
	}
	plain, err := sl.reveal(a.Secret)
	if err != nil {
		return nil, err
	}
	return out, json.Unmarshal([]byte(plain), &out)
}

// newProvider builds the lego DNS-01 provider of an account (secrets decrypted only for this).
func newProvider(a *DNSAccount, sl *sealer) (challenge.Provider, error) {
	sec, err := accountSecrets(a, sl)
	if err != nil {
		return nil, fmt.Errorf("%w – enter the credentials again", err)
	}
	switch a.Provider {
	case "cloudflare", "": // "" = accounts written before the provider was stored
		return newCloudflare(sec["token"])
	case "rfc2136":
		cfg := rfc2136.NewDefaultConfig()
		cfg.Nameserver = a.Config["nameserver"]
		cfg.Zones = slices.Clone(a.Zones) // no SOA lookups needed, also for split-horizon setups
		cfg.TSIGKey, cfg.TSIGSecret = a.Config["tsigKey"], sec["tsigSecret"]
		cfg.TSIGAlgorithm = a.Config["tsigAlgorithm"]
		if cfg.TSIGAlgorithm == "" {
			cfg.TSIGAlgorithm = "hmac-sha256"
		}
		if cfg.TSIGKey != "" {
			cfg.TSIGKey = dns.Fqdn(cfg.TSIGKey)
		}
		cfg.PropagationTimeout, cfg.PollingInterval = 2*time.Minute, 2*time.Second
		cfg.SequenceInterval = 5 * time.Second // one name at a time (lego's default waits a minute between them)
		return rfc2136.NewDNSProviderConfig(cfg)
	case "acmedns":
		return newACMEDNSProvider(a, sl)
	}
	return nil, fmt.Errorf("unknown DNS provider %q", a.Provider)
}

// normalizeZones checks typed-in zones: "Example.com." -> "example.com".
func normalizeZones(in []string) ([]string, error) {
	var out []string
	for _, z := range in {
		for _, z := range splitList(z) {
			z = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(z, "*."), "."))
			if !hostnameRE.MatchString(z) || !strings.Contains(z, ".") {
				return nil, fmt.Errorf("invalid zone %q", z)
			}
			if !slices.Contains(out, z) {
				out = append(out, z)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

// validateConfig checks the non-secret settings of a provider.
func validateConfig(provider string, cfg, sec map[string]string, hasSecret func(string) bool) error {
	switch provider {
	case "rfc2136":
		ns := strings.TrimSpace(cfg["nameserver"])
		host := ns
		if h, p, err := net.SplitHostPort(ns); err == nil {
			host = h
			if _, err := net.LookupPort("udp", p); err != nil {
				return fmt.Errorf("invalid port in %q", ns)
			}
		}
		if host == "" || (net.ParseIP(host) == nil && !hostnameRE.MatchString(host)) {
			return errors.New("enter the DNS server as a host name or IP address, optionally with :port")
		}
		if !slices.Contains(tsigAlgorithms, cfg["tsigAlgorithm"]) {
			return errors.New("choose a TSIG algorithm")
		}
		if cfg["tsigKey"] != "" {
			if !hostnameRE.MatchString(cfg["tsigKey"]) {
				return errors.New("invalid TSIG key name")
			}
			if sec["tsigSecret"] == "" && !hasSecret("tsigSecret") {
				return errors.New("the TSIG secret is required with a TSIG key name")
			}
		}
		if s := sec["tsigSecret"]; s != "" {
			if _, err := base64.StdEncoding.DecodeString(s); err != nil {
				return errors.New("the TSIG secret must be base64, as printed by tsig-keygen or keymgr")
			}
		}
	case "acmedns":
		u, err := url.Parse(strings.TrimSpace(cfg["apiBase"]))
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return errors.New("enter the acme-dns server as a URL, e.g. https://acme-dns.example.com")
		}
		if u.Scheme == "http" && !localOnly(u.Hostname()) {
			return errors.New("use https:// for an acme-dns server on the internet: over http:// its password would travel unencrypted (http:// is allowed for local and private addresses only)")
		}
	}
	return nil
}

// localOnly reports whether host is localhost or resolves only to loopback, private or
// link-local addresses.
func localOnly(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ips := []net.IP{net.ParseIP(host)}
	if ips[0] == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(addrs) == 0 {
			return false
		}
		ips = ips[:0]
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	for _, ip := range ips {
		if !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !cgnat.Contains(ip) {
			return false
		}
	}
	return true
}

// cgnat is 100.64.0.0/10 (shared address space, e.g. Tailscale): not routed on the internet.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// ---- Test: prove that the credentials can create a record that DNS then serves ----

type dnsTestResult struct {
	OK      bool     `json:"ok"`
	Message string   `json:"message"`
	Details []string `json:"details,omitempty"`
}

// testAccount creates a TXT record with a random value, waits until the provider's
// authoritative DNS serves it, and removes it again. For acme-dns, it updates every
// registered name and checks it through the name's CNAME.
func (m *Manager) testAccount(id string) dnsTestResult {
	cfg := m.store.Snapshot()
	a := cfg.dnsAccount(id)
	if a == nil {
		return dnsTestResult{Message: "not found"}
	}
	if a.Provider == "acmedns" {
		return m.testACMEDNS(a)
	}
	if len(a.Zones) == 0 {
		return dnsTestResult{Message: "no zones yet: add at least one zone"}
	}
	p, err := newProvider(a, m.sealer)
	if err != nil {
		return dnsTestResult{Message: err.Error()}
	}
	zone := a.Zones[0]
	name := "routeros-acme-test." + zone
	keyAuth := randomToken()
	info := dns01.GetChallengeInfo(name, keyAuth)
	start := time.Now()
	if err := p.Present(name, "", keyAuth); err != nil {
		return dnsTestResult{Message: fmt.Sprintf("creating a test record in %s failed: %v", zone, err)}
	}
	defer func() { _ = p.CleanUp(name, "", keyAuth) }()

	var servers []string
	if a.Provider == "rfc2136" {
		servers = []string{withPort(a.Config["nameserver"])}
	} else {
		servers = nameServers(zone, splitList(cfg.Settings.DNSResolvers))
	}
	if len(servers) == 0 {
		return dnsTestResult{Message: fmt.Sprintf("created a test record, but found no name servers for %s to check it", zone)}
	}
	seen, err := waitForTXT(info.EffectiveFQDN, info.Value, servers, 40*time.Second)
	if err != nil {
		return dnsTestResult{Message: fmt.Sprintf("created a test record in %s, but %s", zone, err)}
	}
	m.logf("DNS account %q: test record in %s served by %s after %s", a.Name, zone, seen, time.Since(start).Round(time.Second))
	return dnsTestResult{OK: true, Message: fmt.Sprintf("Created a test record in %s, %s served it after %s, and it was removed again.",
		zone, seen, time.Since(start).Round(time.Second))}
}

// netResolver uses the DNS resolvers from Settings when they are set (like the
// propagation check does), otherwise the system's.
func netResolver(resolvers []string) *net.Resolver {
	if len(resolvers) == 0 {
		return net.DefaultResolver
	}
	srv := withPort(resolvers[0])
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, srv)
	}}
}

// nameServers returns the authoritative servers of a zone as host:53.
func nameServers(zone string, resolvers []string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ns, err := netResolver(resolvers).LookupNS(ctx, zone)
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range ns {
		out = append(out, withPort(strings.TrimSuffix(n.Host, ".")))
	}
	return out
}

func withPort(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, "53")
}

// waitForTXT asks the given servers directly (no caches) until one serves the value.
func waitForTXT(fqdn, value string, servers []string, limit time.Duration) (string, error) {
	c := &dns.Client{Timeout: 4 * time.Second}
	deadline := time.Now().Add(limit)
	var last error
	for {
		for _, s := range servers {
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeTXT)
			msg.RecursionDesired = false
			r, _, err := c.Exchange(msg, s)
			if err != nil {
				last = err
				continue
			}
			for _, rr := range r.Answer {
				if t, ok := rr.(*dns.TXT); ok && strings.Join(t.Txt, "") == value {
					return s, nil
				}
			}
			last = fmt.Errorf("%s doesn't serve it yet", s)
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("it didn't show up within %s (%v)", limit, last)
		}
		time.Sleep(2 * time.Second)
	}
}

func randomToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
