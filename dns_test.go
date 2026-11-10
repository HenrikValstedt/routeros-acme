package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/challenge"
)

// fakeCloudflare answers GET /zones like Cloudflare: tok-a sees a.example, tok-b sees
// b.example and sub.a.example, other tokens are rejected.
func fakeCloudflare(t *testing.T) {
	zones := map[string][]string{"tok-a": {"a.example"}, "tok-b": {"b.example", "sub.a.example"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		z, ok := zones[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok || !strings.HasSuffix(r.URL.Path, "/zones") {
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"message": "Invalid API Token"}}})
			return
		}
		var res []map[string]string
		for _, n := range z {
			res = append(res, map[string]string{"name": n})
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": res, "result_info": map[string]int{"total_pages": 1}})
	}))
	old := cfAPI
	cfAPI = srv.URL
	t.Cleanup(func() { cfAPI = old; srv.Close() })
}

func TestZoneRouting(t *testing.T) {
	A := &DNSAccount{ID: "A", Name: "main", Zones: []string{"a.example"}}
	B := &DNSAccount{ID: "B", Name: "second", Zones: []string{"b.example", "sub.a.example"}}
	for _, c := range []struct{ name, acc, zone string }{
		{"a.example", "A", "a.example"}, {"*.a.example", "A", "a.example"}, {"router.a.example", "A", "a.example"},
		{"x.sub.a.example", "B", "sub.a.example"}, // most specific zone wins
		{"b.example", "B", "b.example"}, {"*.B.EXAMPLE", "B", "b.example"}, {"notb.example", "", ""}, {"c.example", "", ""},
	} {
		a, z := zoneOf(c.name, []*DNSAccount{A, B})
		if got := ""; a != nil {
			got = a.ID
			if got != c.acc || z != c.zone {
				t.Errorf("%s: got %s/%s want %s/%s", c.name, got, z, c.acc, c.zone)
			}
		} else if c.acc != "" {
			t.Errorf("%s: no account, want %s", c.name, c.acc)
		}
	}

	cfg := Config{DNS: []*DNSAccount{A, B}}
	r, err := routeCert(cfg, Cert{Domains: []string{"*.a.example", "b.example"}})
	if err != nil || len(r) != 2 || r[0].Account != "A" || r[1].Account != "B" {
		t.Fatalf("one certificate across two accounts: %v %v", r, err)
	}
	if _, err := routeCert(cfg, Cert{Domains: []string{"a.example", "c.example"}}); err == nil || !strings.Contains(err.Error(), "c.example") {
		t.Fatalf("uncovered name must be reported: %v", err)
	}
	if _, err := routeCert(cfg, Cert{Domains: []string{"b.example"}, DNSID: "A"}); err == nil || !strings.Contains(err.Error(), `"main"`) {
		t.Fatalf("chosen account that doesn't cover the name: %v", err)
	}
	if _, err := routeCert(Config{}, Cert{Domains: []string{"a.example"}}); err == nil {
		t.Fatal("no accounts at all must be an error")
	}
	// an account whose zones aren't known yet is the fallback (e.g. right after upgrading)
	U := &DNSAccount{ID: "U", Name: "Cloudflare"}
	if r, err := routeCert(Config{DNS: []*DNSAccount{U}}, Cert{Domains: []string{"anything.example"}}); err != nil || r[0].Account != "U" {
		t.Fatalf("fallback: %v %v", r, err)
	}
}

type fakeProv struct {
	token string
	seen  *[]string
}

func (f fakeProv) Present(d, _, _ string) error {
	*f.seen = append(*f.seen, f.token+":present:"+d)
	return nil
}
func (f fakeProv) CleanUp(d, _, _ string) error {
	*f.seen = append(*f.seen, f.token+":cleanup:"+d)
	return nil
}

func TestMultiAccountProvider(t *testing.T) {
	sl, _ := loadSealer(t.TempDir())
	var seen []string
	old := newCloudflare
	newCloudflare = func(tok string) (challenge.Provider, error) { return fakeProv{tok, &seen}, nil }
	defer func() { newCloudflare = old }()
	cfg := Config{DNS: []*DNSAccount{
		{ID: "A", Name: "main", Token: sl.seal("tok-a"), Zones: []string{"a.example"}},
		{ID: "B", Name: "second", Token: sl.seal("tok-b"), Zones: []string{"b.example"}},
	}}
	p, _, err := dnsProviderFor(cfg, Cert{Domains: []string{"*.a.example", "b.example"}}, sl)
	if err != nil {
		t.Fatal(err)
	}
	p.Present("a.example", "t", "k") // lego passes wildcard names without "*."
	p.Present("b.example", "t", "k")
	p.CleanUp("a.example", "t", "k")
	if got := strings.Join(seen, " "); got != "tok-a:present:a.example tok-b:present:b.example tok-a:cleanup:a.example" {
		t.Fatalf("challenges went to the wrong token: %s", got)
	}
	if err := p.Present("c.example", "t", "k"); err == nil {
		t.Fatal("unknown domain must fail")
	}
}

func TestMigrateSingleToken(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(dir+"/config.json", []byte(`{"settings":{"cfToken":"old-plain-token"},"certs":[{"id":"c1","name":"x","domains":["x.example"]}]}`), 0o600)
	st, _ := OpenStore(dir)
	sl, _ := loadSealer(dir)
	st.SealSecrets(sl)
	if moved, err := st.migrateDNSAccounts(); !moved || err != nil {
		t.Fatal(moved, err)
	}
	c := st.Snapshot()
	if c.Settings.CFToken != "" || len(c.DNS) != 1 || !isSealed(c.DNS[0].Token) {
		t.Fatalf("%+v", c.DNS)
	}
	if v, _ := sl.reveal(c.DNS[0].Token); v != "old-plain-token" {
		t.Fatal("token lost in migration")
	}
	// the existing certificate still has a route (zones not looked up yet -> fallback)
	if _, err := routeCert(c, *c.Certs[0]); err != nil {
		t.Fatal(err)
	}
	if moved, _ := st.migrateDNSAccounts(); moved {
		t.Fatal("migration must run once")
	}
}

func TestDNSAccountsAPI(t *testing.T) {
	fakeCloudflare(t)
	a, srv := newTestApp(t)
	admin := newClient(t, srv)
	admin.expect(200, "POST", "/api/setup", map[string]string{"code": a.setupCode, "username": "boss", "password": "supersecret"})
	admin.turnOn2FA()

	if s := admin.expect(400, "POST", "/api/dns-accounts", map[string]any{"name": "bad", "token": "wrong"}); !strings.Contains(s, "Invalid API Token") {
		t.Fatal(s)
	}
	admin.expect(200, "POST", "/api/dns-accounts", map[string]any{"name": "main", "token": "tok-a"})
	admin.expect(200, "POST", "/api/dns-accounts", map[string]any{"token": "tok-b"}) // name defaults to first zone

	var st struct {
		DNS []dnsAccountView          `json:"dnsAccounts"`
		R   map[string]map[string]any `json:"dnsRoutes"`
	}
	raw := admin.expect(200, "GET", "/api/state", nil)
	json.Unmarshal([]byte(raw), &st)
	if len(st.DNS) != 2 || st.DNS[1].Name != "b.example" || strings.Join(st.DNS[1].Zones, ",") != "b.example,sub.a.example" || !st.DNS[0].HasToken {
		t.Fatalf("%+v", st.DNS)
	}
	if strings.Contains(raw, "tok-a") || strings.Contains(raw, `"token"`) {
		t.Fatal("token sent to the browser")
	}
	ids := map[string]string{st.DNS[0].Name: st.DNS[0].ID, st.DNS[1].Name: st.DNS[1].ID}

	// certificates: covered names are accepted, uncovered ones rejected before issuing
	if s := admin.expect(400, "POST", "/api/certs", map[string]any{"name": "c", "domains": []string{"www.c.example"}}); !strings.Contains(s, "www.c.example") {
		t.Fatal(s)
	}
	admin.expect(200, "POST", "/api/certs", map[string]any{"name": "both", "domains": []string{"*.a.example", "b.example"}})
	admin.expect(200, "POST", "/api/certs", map[string]any{"name": "pinned", "domains": []string{"b.example"}, "dnsAccountId": ids["b.example"]})
	admin.expect(400, "POST", "/api/certs", map[string]any{"name": "wrong", "domains": []string{"a.example"}, "dnsAccountId": ids["b.example"]})
	json.Unmarshal([]byte(admin.expect(200, "GET", "/api/state", nil)), &st)
	for _, c := range a.store.Snapshot().Certs {
		if c.Name == "both" {
			routes, _ := json.Marshal(st.R[c.ID]["routes"])
			if !strings.Contains(string(routes), ids["main"]) || !strings.Contains(string(routes), ids["b.example"]) {
				t.Fatalf("routes: %s", routes)
			}
		}
	}

	// a certificate pinned to an account blocks deleting it
	admin.expect(400, "DELETE", "/api/dns-accounts/"+ids["b.example"], nil)
	admin.expect(200, "POST", "/api/dns-accounts/"+ids["main"]+"/refresh", map[string]any{})

	// viewers see accounts but can't change them
	admin.expect(200, "POST", "/api/users", map[string]string{"username": "vic", "role": "viewer", "password": "vicpassword"})
	v := newClient(t, srv)
	v.expect(200, "POST", "/api/login", map[string]string{"username": "vic", "password": "vicpassword"})
	v.expect(403, "POST", "/api/dns-accounts", map[string]any{"name": "x", "token": "tok-a"})
	if s := v.expect(200, "GET", "/api/state", nil); !strings.Contains(s, `"dnsAccounts"`) || strings.Contains(s, "tok-") {
		t.Fatal("viewer state")
	}
}
