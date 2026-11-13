package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// turnOn2FA sets up TOTP for the signed-in user and returns the secret.
func (c *client) turnOn2FA() string {
	c.t.Helper()
	var setup struct {
		Secret string `json:"secret"`
		QR     string `json:"qr"`
	}
	if err := json.Unmarshal([]byte(c.expect(200, "POST", "/api/me/2fa/setup", map[string]string{})), &setup); err != nil {
		c.t.Fatal(err)
	}
	c.expect(200, "POST", "/api/me/2fa/enable", map[string]string{"code": totpCode(setup.Secret, time.Now())})
	return setup.Secret
}

type client struct {
	t   *testing.T
	srv *httptest.Server
	c   *http.Client
}

func newClient(t *testing.T, srv *httptest.Server) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t, srv, &http.Client{Jar: jar}}
}

func (c *client) do(method, path string, body any) (int, string) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, rd)
	if method != "GET" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

func (c *client) expect(code int, method, path string, body any) string {
	c.t.Helper()
	got, msg := c.do(method, path, body)
	if got != code {
		c.t.Fatalf("%s %s: got %d (%s), want %d", method, path, got, msg, code)
	}
	return msg
}

func newTestApp(t *testing.T) (*app, *httptest.Server) {
	t.Setenv("ADMIN_PASSWORD", "")
	dir := t.TempDir()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{store: st, mgr: NewManager(st, dir), dataDir: dir, sessions: &sessionStore{m: map[string]session{}},
		ceremonies: &ceremonyStore{m: map[string]ceremony{}}}
	a.throttle, a.mailThrottle, a.acctThrottle = newThrottle(), newThrottle(), newThrottleN(10, 15*time.Minute)
	a.mgr.sealer, _ = loadSealer(dir)
	a.otpFresh = 5 * time.Minute
	if err := a.initUsers(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	return a, srv
}

func TestAuthFlow(t *testing.T) {
	a, srv := newTestApp(t)
	if a.setupCode == "" {
		t.Fatal("no setup code generated on first run")
	}
	anon := newClient(t, srv)

	// everything is locked before setup
	anon.expect(401, "GET", "/api/state", nil)
	if s := anon.expect(200, "GET", "/api/session", nil); !strings.Contains(s, `"setupRequired":true`) {
		t.Fatal(s)
	}
	// setup needs the code from the log
	anon.expect(400, "POST", "/api/setup", map[string]string{"code": "wrong", "username": "boss", "password": "supersecret"})
	anon.expect(400, "POST", "/api/setup", map[string]string{"code": a.setupCode, "username": "boss", "password": "short"})
	admin := newClient(t, srv)
	admin.expect(200, "POST", "/api/setup", map[string]string{"code": a.setupCode, "username": "boss", "password": "supersecret"})
	admin.expect(403, "GET", "/api/state", nil) // admins must set up 2FA before anything else
	admin.turnOn2FA()
	// setup cannot be repeated
	anon.expect(400, "POST", "/api/setup", map[string]string{"code": "", "username": "evil", "password": "supersecret"})

	// admin is logged in by setup
	if s := admin.expect(200, "GET", "/api/state", nil); !strings.Contains(s, `"role":"admin"`) {
		t.Fatal(s)
	}
	// CSRF guard: non-JSON post rejected
	req, _ := http.NewRequest("POST", srv.URL+"/api/run", strings.NewReader("x=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, _ := admin.c.Do(req); resp.StatusCode != 415 {
		t.Fatalf("form post: %d", resp.StatusCode)
	}

	// create a viewer
	admin.expect(200, "POST", "/api/users", map[string]string{"username": "watcher", "role": "viewer", "password": "viewerpass"})
	admin.expect(400, "POST", "/api/users", map[string]string{"username": "WATCHER", "role": "viewer", "password": "viewerpass"}) // duplicate
	admin.expect(400, "POST", "/api/users", map[string]string{"username": "x", "role": "root", "password": "viewerpass"})         // bad role

	viewer := newClient(t, srv)
	viewer.expect(401, "POST", "/api/login", map[string]string{"username": "watcher", "password": "nope-nope"})
	viewer.expect(200, "POST", "/api/login", map[string]string{"username": "watcher", "password": "viewerpass"})
	viewer.expect(200, "GET", "/api/state", nil)
	viewer.expect(200, "GET", "/api/logs", nil)
	for _, p := range [][2]string{{"PUT", "/api/settings"}, {"POST", "/api/run"}, {"POST", "/api/certs"}, {"POST", "/api/routers"},
		{"POST", "/api/routers/x/deploy"}, {"GET", "/api/users"}, {"POST", "/api/users"}, {"DELETE", "/api/users/x"}} {
		viewer.expect(403, p[0], p[1], map[string]string{})
	}
	viewer.expect(200, "PUT", "/api/me/password", map[string]string{"current": "viewerpass", "new": "viewerpass2"})

	// last-admin protection
	var users []userView
	_ = json.Unmarshal([]byte(admin.expect(200, "GET", "/api/users", nil)), &users)
	var bossID, watcherID string
	for _, u := range users {
		if u.Username == "boss" {
			bossID = u.ID
		} else {
			watcherID = u.ID
		}
	}
	admin.expect(400, "POST", "/api/users", map[string]string{"id": bossID, "username": "boss", "role": "viewer"})
	admin.expect(400, "DELETE", "/api/users/"+bossID, nil)

	// admin resets viewer's password -> viewer's session ends
	admin.expect(200, "POST", "/api/users", map[string]string{"id": watcherID, "username": "watcher", "role": "viewer", "password": "resetpass1"})
	viewer.expect(401, "GET", "/api/state", nil)

	// promote viewer to admin, then it can manage users; deleting removes access
	admin.expect(200, "POST", "/api/users", map[string]string{"id": watcherID, "username": "watcher", "role": "admin"})
	viewer.expect(200, "POST", "/api/login", map[string]string{"username": "watcher", "password": "resetpass1"})
	viewer.expect(403, "GET", "/api/users", nil) // a new admin must set up 2FA first
	viewer.turnOn2FA()
	viewer.expect(200, "GET", "/api/users", nil)
	admin.expect(200, "DELETE", "/api/users/"+watcherID, nil)
	viewer.expect(401, "GET", "/api/state", nil)

	// logout
	admin.expect(200, "POST", "/api/logout", nil)
	admin.expect(401, "GET", "/api/state", nil)

	// brute force throttling
	bf := newClient(t, srv)
	for i := 0; i < 5; i++ {
		bf.expect(401, "POST", "/api/login", map[string]string{"username": "boss", "password": "guess"})
	}
	bf.expect(429, "POST", "/api/login", map[string]string{"username": "boss", "password": "supersecret"})

	// hashes are never exposed
	if strings.Contains(admin.expect(401, "GET", "/api/users", nil), "$2a$") {
		t.Fatal("hash leaked")
	}
}

func TestEnvBootstrap(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ADMIN_USER", "ops")
	t.Setenv("ADMIN_PASSWORD", "fromenvpass")
	st, _ := OpenStore(dir)
	a := &app{store: st}
	if err := a.initUsers(); err != nil {
		t.Fatal(err)
	}
	c := st.Snapshot()
	if len(c.Users) != 1 || c.Users[0].Username != "ops" || c.Users[0].Role != RoleAdmin || a.setupCode != "" {
		t.Fatalf("%+v", c.Users)
	}
}
