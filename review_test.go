package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Findings from an independent review (v1.6.1), one test each.

// Extra commands run on the router: changing them needs a fresh 2FA code.
func TestExtraCommandsNeedFreshCode(t *testing.T) {
	a, srv := newTestApp(t)
	admin := newClient(t, srv)
	admin.expect(200, "POST", "/api/setup", map[string]string{"code": a.setupCode, "username": "boss", "password": "supersecret"})
	admin.turnOn2FA()
	_ = a.store.Update(func(c *Config) error {
		c.Routers = []*Router{{ID: "r1", Name: "gw", ExtraCmds: "/log info hello"}}
		return nil
	})
	stale := func() {
		a.sessions.mu.Lock()
		for k, s := range a.sessions.m {
			s.fresh, s.oneShot = time.Time{}, false
			a.sessions.m[k] = s
		}
		a.sessions.mu.Unlock()
	}
	stale()
	// same commands (other fields changed): no code needed
	admin.expect(200, "POST", "/api/routers", map[string]any{"id": "r1", "name": "gw2", "enabled": true, "extraCommands": "/log info hello"})
	// new commands: refused without a fresh code, and nothing is saved
	if msg := admin.expect(403, "POST", "/api/routers", map[string]any{"id": "r1", "name": "gw2", "extraCommands": "/system reboot"}); !strings.HasPrefix(msg, "otp_required") {
		t.Fatal(msg)
	}
	if got := a.store.Snapshot().router("r1").ExtraCmds; got != "/log info hello" {
		t.Fatalf("saved without a fresh code: %q", got)
	}
	a.sessions.mu.Lock()
	for k, s := range a.sessions.m {
		s.fresh = time.Now()
		a.sessions.m[k] = s
	}
	a.sessions.mu.Unlock()
	admin.expect(200, "POST", "/api/routers", map[string]any{"id": "r1", "name": "gw2", "extraCommands": "/system reboot"})
}

// 10 wrong passwords for one account, from different addresses, lock that account.
func TestAccountLockout(t *testing.T) {
	a, srv := newTestApp(t)
	admin := newClient(t, srv)
	admin.expect(200, "POST", "/api/setup", map[string]string{"code": a.setupCode, "username": "boss", "password": "supersecret"})
	for i := 0; i < 10; i++ {
		a.throttle.ok("127.0.0.1") // pretend each try comes from a new address (the IP limit is 5)
		newClient(t, srv).expect(401, "POST", "/api/login", map[string]string{"username": "Boss", "password": "wrong-password"})
	}
	a.throttle.ok("127.0.0.1")
	if msg := newClient(t, srv).expect(429, "POST", "/api/login", map[string]string{"username": "boss", "password": "supersecret"}); !strings.Contains(msg, "this account") {
		t.Fatal(msg)
	}
	// other accounts are not affected
	if a.acctThrottle.blocked(accountKey("someone-else")) {
		t.Fatal("other accounts must not be locked")
	}
}

// acme-dns over http:// only for local and private addresses.
func TestACMEDNSHTTPOnlyLocal(t *testing.T) {
	for url, ok := range map[string]bool{
		"https://auth.acme-dns.io": true, "http://127.0.0.1:8053": true, "http://192.168.1.5": true,
		"http://localhost": true, "http://[fd00::5]": true, "http://203.0.113.9": false, "http://8.8.8.8": false,
	} {
		err := validateConfig("acmedns", map[string]string{"apiBase": url}, nil, nil)
		if ok != (err == nil) {
			t.Errorf("%s: %v", url, err)
		}
	}
}

// config.json is replaced atomically; no temporary file is left behind.
func TestStoreSaveAtomic(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(c *Config) error { c.Settings.Email = "a@example.com"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json.tmp")); !os.IsNotExist(err) {
		t.Fatal("temporary file left behind")
	}
	st2, _ := OpenStore(dir)
	if st2.Snapshot().Settings.Email != "a@example.com" {
		t.Fatal("not saved")
	}
}
