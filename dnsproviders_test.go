package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
)

// fakeACMEDNS is a minimal acme-dns API: /register and /update.
type fakeACMEDNS struct {
	mu      sync.Mutex
	n       int
	updates map[string]string // subdomain -> txt
	srv     *httptest.Server
}

func newFakeACMEDNS(t *testing.T) *fakeACMEDNS {
	f := &fakeACMEDNS{updates: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/register":
			f.n++
			sub := strings.Repeat(string(rune('a'+f.n)), 8)
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]string{"username": "u-" + sub, "password": "p-" + sub, "subdomain": sub, "fulldomain": sub + ".auth.acme.test"})
		case "/update":
			var in struct{ Subdomain, Txt string }
			json.NewDecoder(r.Body).Decode(&in)
			if r.Header.Get("X-Api-User") != "u-"+in.Subdomain || r.Header.Get("X-Api-Key") != "p-"+in.Subdomain || len(in.Txt) != 43 {
				http.Error(w, `{"error":"forbidden"}`, 401)
				return
			}
			f.updates[in.Subdomain] = in.Txt
			io.WriteString(w, `{"txt":"`+in.Txt+`"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func TestDNSProvidersAPI(t *testing.T) {
	a, srv := newTestApp(t)
	admin := newClient(t, srv)
	admin.expect(200, "POST", "/api/setup", map[string]string{"code": a.setupCode, "username": "boss", "password": "supersecret"})
	admin.turnOn2FA()

	rfc := func(cfg map[string]string, sec map[string]string, zones ...string) map[string]any {
		return map[string]any{"provider": "rfc2136", "config": cfg, "secrets": sec, "zones": zones}
	}
	good := map[string]string{"nameserver": "192.0.2.53", "tsigKey": "acme-update", "tsigAlgorithm": "hmac-sha256"}
	secret := map[string]string{"tsigSecret": "c2VjcmV0LXRzaWcta2V5LWZvci10ZXN0cw=="}
	admin.expect(400, "POST", "/api/dns-accounts", map[string]any{"provider": "route53"})
	admin.expect(400, "POST", "/api/dns-accounts", rfc(good, secret))                              // no zones
	admin.expect(400, "POST", "/api/dns-accounts", rfc(good, map[string]string{}, "example.test")) // key without secret
	admin.expect(400, "POST", "/api/dns-accounts", rfc(good, map[string]string{"tsigSecret": "not base64!"}, "example.test"))
	admin.expect(400, "POST", "/api/dns-accounts", rfc(map[string]string{"nameserver": "bad host!"}, nil, "example.test"))
	admin.expect(400, "POST", "/api/dns-accounts", rfc(good, secret, "not a zone"))
	admin.expect(200, "POST", "/api/dns-accounts", rfc(good, secret, "Example.TEST.", "*.other.test"))

	fake := newFakeACMEDNS(t)
	admin.expect(400, "POST", "/api/dns-accounts", map[string]any{"provider": "acmedns", "config": map[string]string{"apiBase": "ftp://x"}, "zones": []string{"acme.example"}})
	admin.expect(200, "POST", "/api/dns-accounts", map[string]any{"provider": "acmedns", "name": "acme", "config": map[string]string{"apiBase": fake.srv.URL}, "zones": []string{"acme.example"}})

	var st struct {
		DNS []dnsAccountView `json:"dnsAccounts"`
	}
	raw := admin.expect(200, "GET", "/api/state", nil)
	json.Unmarshal([]byte(raw), &st)
	if len(st.DNS) != 2 || strings.Join(st.DNS[0].Zones, ",") != "example.test,other.test" || st.DNS[0].Name != "example.test" || !st.DNS[0].HasSecret {
		t.Fatalf("%+v", st.DNS)
	}
	if strings.Contains(raw, "c2VjcmV0") || strings.Contains(raw, `"secret":"v1:`) {
		t.Fatal("secrets sent to the browser")
	}
	rfcID, acmeID := st.DNS[0].ID, st.DNS[1].ID

	// editing without the secret keeps it; the provider can't change
	admin.expect(200, "POST", "/api/dns-accounts", map[string]any{"id": rfcID, "provider": "rfc2136", "config": good, "zones": []string{"example.test"}})
	admin.expect(400, "POST", "/api/dns-accounts", map[string]any{"id": rfcID, "provider": "acmedns", "config": map[string]string{"apiBase": fake.srv.URL}, "zones": []string{"example.test"}})
	sec, err := accountSecrets(a.store.Snapshot().dnsAccount(rfcID), a.mgr.sealer)
	if err != nil || sec["tsigSecret"] != secret["tsigSecret"] {
		t.Fatal("TSIG secret not kept", sec, err)
	}
	if p, err := newProvider(a.store.Snapshot().dnsAccount(rfcID), a.mgr.sealer); err != nil || p == nil {
		t.Fatal("rfc2136 provider", err)
	}

	// a certificate behind acme-dns gets a registration; the CNAME is missing, so issuing waits for it
	admin.expect(200, "POST", "/api/certs", map[string]any{"name": "r", "domains": []string{"*.router.acme.example", "router.acme.example"}})
	if err := a.mgr.syncACMEDNS(acmeID); err != nil {
		t.Fatal(err)
	}
	acc := a.store.Snapshot().dnsAccount(acmeID)
	if len(acc.ACMEDNS) != 1 || acc.ACMEDNS[0].Name != "router.acme.example" || !isSealed(acc.ACMEDNS[0].Password) || acc.ACMEDNS[0].CNAMEOK {
		t.Fatalf("%+v", acc.ACMEDNS)
	}
	raw = admin.expect(200, "GET", "/api/state", nil)
	if !strings.Contains(raw, `"record":"_acme-challenge.router.acme.example"`) || strings.Contains(raw, "p-") {
		t.Fatal("CNAME to create not shown, or acme-dns password leaked")
	}
	cert := a.store.Snapshot().Certs[0]
	if err := a.mgr.acmeDNSReady(*cert); err == nil || !strings.Contains(err.Error(), "_acme-challenge.router.acme.example → ") {
		t.Fatal("issuing must wait for the CNAME:", err)
	}
	// the provider sends the challenge value to acme-dns with the registration's credentials
	p, err := newProvider(acc, a.mgr.sealer)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Present("router.acme.example", "", "key-auth"); err != nil {
		t.Fatal(err)
	}
	if len(fake.updates) != 1 || fake.updates[acc.ACMEDNS[0].Subdomain] != dns01.GetChallengeInfo("router.acme.example", "key-auth").Value {
		t.Fatal("challenge value not sent to acme-dns", fake.updates)
	}
	if err := p.Present("other.acme.example", "", "key-auth"); err == nil {
		t.Fatal("an unregistered name must fail")
	}

	// both accounts' secrets are part of the re-encryption list
	var n int
	a.store.Read(func(c *Config) {
		for _, f := range sealedFields(c) {
			if isSealed(*f.p) && (strings.Contains(f.what, "credentials") || strings.Contains(f.what, "acme-dns registration")) {
				n++
			}
		}
	})
	if n != 2 {
		t.Fatalf("%d DNS secrets in sealedFields, want 2", n)
	}
}

func TestNormalizeZones(t *testing.T) {
	z, err := normalizeZones([]string{"B.example.", "a.example, b.example", "*.c.example"})
	if err != nil || strings.Join(z, ",") != "a.example,b.example,c.example" {
		t.Fatal(z, err)
	}
	for _, bad := range []string{"localhost", "a b.example", "x/y.example", "-"} {
		if _, err := normalizeZones([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNamecheapAccount(t *testing.T) {
	a, srv := newTestApp(t)
	admin := newClient(t, srv)
	admin.expect(200, "POST", "/api/setup", map[string]string{"code": a.setupCode, "username": "boss", "password": "supersecret"})
	admin.turnOn2FA()

	nc := func(cfg, sec map[string]string, zones ...string) map[string]any {
		return map[string]any{"provider": "namecheap", "config": cfg, "secrets": sec, "zones": zones}
	}
	key := map[string]string{"apiKey": "0123456789abcdef0123456789abcdef"}
	user := map[string]string{"apiUser": "someone"}
	admin.expect(400, "POST", "/api/dns-accounts", nc(map[string]string{}, key, "example.test"))                                                // no user
	admin.expect(400, "POST", "/api/dns-accounts", nc(user, map[string]string{}, "example.test"))                                               // no key
	admin.expect(400, "POST", "/api/dns-accounts", nc(user, map[string]string{"apiKey": "short!"}, "example.test"))                             // bad key
	admin.expect(400, "POST", "/api/dns-accounts", nc(map[string]string{"apiUser": "someone", "clientIP": "2001:db8::1"}, key, "example.test")) // not IPv4
	admin.expect(400, "POST", "/api/dns-accounts", nc(user, key))                                                                               // no zones
	admin.expect(200, "POST", "/api/dns-accounts", nc(map[string]string{"apiUser": "someone", "clientIP": "192.0.2.10"}, key, "example.test"))

	acc := a.store.Snapshot().DNS[0]
	if acc.Provider != "namecheap" || acc.Config["clientIP"] != "192.0.2.10" || !isSealed(acc.Secret) || strings.Contains(acc.Secret, key["apiKey"]) {
		t.Fatalf("%+v", acc)
	}
	raw := admin.expect(200, "GET", "/api/state", nil)
	if strings.Contains(raw, key["apiKey"]) {
		t.Fatal("API key sent to the browser")
	}

	var got [3]string
	orig := newNamecheap
	t.Cleanup(func() { newNamecheap = orig })
	newNamecheap = func(u, k, ip string) (challenge.Provider, error) {
		got = [3]string{u, k, ip}
		return orig(u, k, ip) // the IP is given, so nothing is looked up
	}
	if p, err := newProvider(acc, a.mgr.sealer); err != nil || p == nil {
		t.Fatal(err)
	}
	if got != [3]string{"someone", key["apiKey"], "192.0.2.10"} {
		t.Fatal(got)
	}

	// certificates in its zone wait as long as Namecheap needs
	admin.expect(200, "POST", "/api/certs", map[string]any{"name": "nc", "domains": []string{"*.example.test"}})
	p, _, err := dnsProviderFor(a.store.Snapshot(), *a.store.Snapshot().Certs[0], a.mgr.sealer)
	if err != nil {
		t.Fatal(err)
	}
	if to, _ := p.(challenge.ProviderTimeout).Timeout(); to != 10*time.Minute {
		t.Fatal("timeout", to)
	}
}
