package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func reqFrom(remote string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func TestClientIP(t *testing.T) {
	p, err := parseTrustedProxies("172.18.0.0/16, 10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	none, _ := parseTrustedProxies("")
	cases := []struct {
		name   string
		p      proxyTrust
		remote string
		hdr    map[string]string
		want   string
	}{
		{"no proxy configured ignores XFF", none, "203.0.113.9:1234", map[string]string{"X-Forwarded-For": "1.2.3.4"}, "203.0.113.9"},
		{"untrusted peer can't spoof", p, "203.0.113.9:1234", map[string]string{"X-Forwarded-For": "1.2.3.4"}, "203.0.113.9"},
		{"trusted proxy", p, "172.18.0.2:5555", map[string]string{"X-Forwarded-For": "198.51.100.7"}, "198.51.100.7"},
		{"client-sent XFF is skipped", p, "172.18.0.2:5555", map[string]string{"X-Forwarded-For": "6.6.6.6, 198.51.100.7"}, "198.51.100.7"},
		{"chain of trusted proxies", p, "172.18.0.2:5555", map[string]string{"X-Forwarded-For": "198.51.100.7, 10.0.0.5"}, "198.51.100.7"},
		{"garbage stops the walk", p, "172.18.0.2:5555", map[string]string{"X-Forwarded-For": "junk, 10.0.0.5"}, "10.0.0.5"},
		{"X-Real-IP fallback", p, "172.18.0.2:5555", map[string]string{"X-Real-IP": "198.51.100.8"}, "198.51.100.8"},
		{"trusted proxy without headers", p, "172.18.0.2:5555", nil, "172.18.0.2"},
		{"ipv6 peer", p, "[2001:db8::1]:443", nil, "2001:db8::1"},
	}
	for _, c := range cases {
		if got := c.p.clientIP(reqFrom(c.remote, c.hdr)); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}

	priv, _ := parseTrustedProxies("private")
	if got := priv.clientIP(reqFrom("192.168.1.10:1", map[string]string{"X-Forwarded-For": "198.51.100.7"})); got != "198.51.100.7" {
		t.Errorf("private keyword: %s", got)
	}
	if _, err := parseTrustedProxies("not-an-ip"); err == nil {
		t.Error("expected error for bad TRUSTED_PROXIES")
	}
}

func TestIsHTTPS(t *testing.T) {
	p, _ := parseTrustedProxies("172.18.0.0/16")
	if !p.isHTTPS(reqFrom("172.18.0.2:1", map[string]string{"X-Forwarded-Proto": "https"})) {
		t.Error("trusted proxy https not detected")
	}
	if p.isHTTPS(reqFrom("203.0.113.9:1", map[string]string{"X-Forwarded-Proto": "https"})) {
		t.Error("untrusted X-Forwarded-Proto must be ignored")
	}
	r := reqFrom("203.0.113.9:1", nil)
	r.TLS = &tls.ConnectionState{}
	if !p.isHTTPS(r) {
		t.Error("direct TLS not detected")
	}
}

func TestBasePathAndCookies(t *testing.T) {
	a, _ := newTestApp(t)
	a.basePath = "/certs"
	a.proxy, _ = parseTrustedProxies("127.0.0.1")
	srv := httptest.NewServer(withBasePath(a.basePath, a.routes()))
	defer srv.Close()
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	get := func(path string) (int, string) {
		resp, err := noRedirect.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("Location") + string(b)
	}
	if c, loc := get("/certs"); c != 301 || !strings.HasPrefix(loc, "/certs/") {
		t.Errorf("redirect: %d %s", c, loc)
	}
	if c, body := get("/certs/"); c != 200 || !strings.Contains(body, "<title>") {
		t.Errorf("prefixed index: %d", c)
	}
	if c, _ := get("/certs/api/session"); c != 200 {
		t.Errorf("prefixed api: %d", c)
	}
	if c, _ := get("/api/session"); c != 200 { // proxy that strips the prefix
		t.Errorf("stripped api: %d", c)
	}
	if c, _ := get("/healthz"); c != 200 {
		t.Errorf("healthz: %d", c)
	}

	// cookie gets base path + Secure when the trusted proxy says https
	body := `{"code":"` + a.setupCode + `","username":"boss","password":"supersecret"}`
	req, _ := http.NewRequest("POST", srv.URL+"/certs/api/setup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	sc := resp.Header.Get("Set-Cookie")
	if resp.StatusCode != 200 || !strings.Contains(sc, "Path=/certs/") || !strings.Contains(sc, "Secure") || !strings.Contains(sc, "HttpOnly") {
		t.Fatalf("status %d cookie %q", resp.StatusCode, sc)
	}
	// real client IP is what gets logged
	found := false
	for _, l := range a.mgr.Logs() {
		found = found || strings.Contains(l.Msg, "from 198.51.100.7")
	}
	if !found {
		t.Error("client IP from X-Forwarded-For not used in log")
	}
}

func TestUntrustedProxyHint(t *testing.T) {
	p, _ := parseTrustedProxies("10.0.0.1")
	none, _ := parseTrustedProxies("")
	r := reqFrom("172.29.20.1:5555", map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-For": "192.168.1.50"})
	if peer, ok := none.untrustedProxy(r); !ok || peer != "172.29.20.1" {
		t.Fatalf("untrusted proxy not detected: %q %v", peer, ok)
	}
	if h := none.proxyHint(r); !strings.Contains(h, "TRUSTED_PROXIES=172.29.20.1") {
		t.Fatal(h)
	}
	if _, ok := p.untrustedProxy(reqFrom("10.0.0.1:1", map[string]string{"X-Forwarded-Proto": "https"})); ok {
		t.Fatal("a trusted proxy must not be reported")
	}
	if _, ok := none.untrustedProxy(reqFrom("192.168.1.50:1", nil)); ok {
		t.Fatal("a direct visitor (no proxy headers) must not be reported")
	}

	// passkeys explain the fix, and the log warns once per address
	a, srv := newTestApp(t)
	_ = srv
	if _, _, err := a.relyingParty(func() *http.Request {
		x := reqFrom("172.29.20.1:5555", map[string]string{"X-Forwarded-Proto": "https"})
		x.Host = "certs.example.com"
		return x
	}()); err == nil || !strings.Contains(err.Error(), "TRUSTED_PROXIES=172.29.20.1") {
		t.Fatalf("passkey reason: %v", err)
	}
	a.warnProxyOnce("172.29.20.1")
	a.warnProxyOnce("172.29.20.1")
	n := 0
	for _, l := range a.mgr.Logs() {
		if strings.Contains(l.Msg, "isn't in TRUSTED_PROXIES") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("warned %d times, want once", n)
	}
}
