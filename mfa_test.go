package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B test vectors (SHA1, secret "12345678901234567890"), last 6 digits.
func TestTOTPVectors(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	for _, v := range []struct {
		unix int64
		code string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}} {
		if got := totpCode(secret, time.Unix(v.unix, 0)); got != v.code {
			t.Errorf("t=%d: got %s want %s", v.unix, got, v.code)
		}
	}
	now := time.Unix(1111111111, 0)
	step, ok := checkTOTP(secret, "050471", 0, now)
	if !ok {
		t.Fatal("valid code rejected")
	}
	if _, ok := checkTOTP(secret, "050471", step, now); ok {
		t.Fatal("a used code must not work twice")
	}
	if _, ok := checkTOTP(secret, totpCode(secret, now.Add(-30*time.Second)), 0, now); !ok {
		t.Fatal("previous step should be accepted (clock drift)")
	}
	if _, ok := checkTOTP(secret, totpCode(secret, now.Add(-90*time.Second)), 0, now); ok {
		t.Fatal("old code accepted")
	}
	if svg, err := qrSVG(otpauthURI(secret, "boss", "RouterOS ACME")); err != nil || !strings.HasPrefix(svg, "<svg") {
		t.Fatal("qr", err)
	}
	if u := otpauthURI(secret, "boss", "RouterOS ACME"); !strings.HasPrefix(u, "otpauth://totp/RouterOS%20ACME:boss?") || !strings.Contains(u, "secret="+secret) {
		t.Fatal(u)
	}
}

// nextCode returns a code for the step after the last used one (still inside the accepted window).
func nextCode(secret string) string { return totpCode(secret, time.Now().Add(30*time.Second)) }

func TestTwoFactorFlow(t *testing.T) {
	a, srv := newTestApp(t)
	admin := newClient(t, srv)
	admin.expect(200, "POST", "/api/setup", map[string]string{"code": a.setupCode, "username": "boss", "password": "supersecret"})

	// until 2FA is on, an admin can only reach the setup
	if s := admin.expect(200, "GET", "/api/session", nil); !strings.Contains(s, `"mfaSetupRequired":true`) {
		t.Fatal(s)
	}
	for _, p := range [][2]string{{"GET", "/api/state"}, {"GET", "/api/users"}, {"PUT", "/api/settings"}, {"POST", "/api/devices/enroll"}} {
		if s := admin.expect(403, p[0], p[1], map[string]string{}); !strings.HasPrefix(s, "mfa_setup_required") {
			t.Fatalf("%v: %s", p, s)
		}
	}
	var setup struct{ Secret, QR, URI string }
	_ = json.Unmarshal([]byte(admin.expect(200, "POST", "/api/me/2fa/setup", map[string]string{})), &setup)
	if !strings.HasPrefix(setup.QR, "<svg") || len(setup.Secret) != 32 {
		t.Fatalf("setup: %+v", setup)
	}
	admin.expect(400, "POST", "/api/me/2fa/enable", map[string]string{"code": "000000"})
	var en struct{ Recovery []string }
	_ = json.Unmarshal([]byte(admin.expect(200, "POST", "/api/me/2fa/enable", map[string]string{"code": totpCode(setup.Secret, time.Now())})), &en)
	if len(en.Recovery) != 10 {
		t.Fatalf("recovery codes: %v", en.Recovery)
	}
	admin.expect(200, "GET", "/api/state", nil)
	if strings.Contains(a.store.Snapshot().Users[0].TOTPSecret, setup.Secret) {
		t.Fatal("2FA secret stored in plain text")
	}

	// sign in again: password, then code
	admin.expect(200, "POST", "/api/logout", nil)
	if s := admin.expect(200, "POST", "/api/login", map[string]string{"username": "boss", "password": "supersecret"}); !strings.Contains(s, `"mfa":true`) {
		t.Fatal(s)
	}
	admin.expect(401, "GET", "/api/state", nil) // not signed in yet
	if s := admin.expect(200, "GET", "/api/session", nil); !strings.Contains(s, `"mfaPending":true`) {
		t.Fatal(s)
	}
	admin.expect(401, "POST", "/api/login/otp", map[string]string{"code": "123456"})
	code := nextCode(setup.Secret)
	admin.expect(200, "POST", "/api/login/otp", map[string]string{"code": code})
	admin.expect(200, "GET", "/api/state", nil)
	if !logged(a, `user "boss" signed in from 127.0.0.1 with password + 2FA code`) {
		t.Fatal("sign-in with code not logged")
	}

	// the same code can't be used again
	other := newClient(t, srv)
	other.expect(200, "POST", "/api/login", map[string]string{"username": "boss", "password": "supersecret"})
	other.expect(401, "POST", "/api/login/otp", map[string]string{"code": code})
	// a recovery code works, once
	if s := other.expect(200, "POST", "/api/login/otp", map[string]string{"code": strings.ToUpper(en.Recovery[0])}); !strings.Contains(s, `"usedRecovery":true`) || !strings.Contains(s, `"recoveryLeft":9`) {
		t.Fatal(s)
	}
	if !logged(a, `user "boss" signed in from 127.0.0.1 with password + recovery code (9 left)`) {
		t.Fatal("sign-in with recovery code not logged")
	}
	third := newClient(t, srv)
	third.expect(200, "POST", "/api/login", map[string]string{"username": "boss", "password": "supersecret"})
	third.expect(401, "POST", "/api/login/otp", map[string]string{"code": en.Recovery[0]})

	// sensitive actions need a fresh code
	a.otpFresh = 0
	for _, req := range []struct {
		m, p string
		body any
	}{
		{"POST", "/api/devices/enroll", map[string]string{}},
		{"POST", "/api/dns-accounts", map[string]any{"name": "x", "token": "new-token"}},
		{"POST", "/api/users", map[string]string{"username": "eve", "role": "admin", "password": "evepassword"}},
		{"POST", "/api/invites", map[string]string{"email": "x@example.org", "role": "admin"}},
		{"PUT", "/api/mail", map[string]any{"host": "smtp", "port": 25, "security": "none", "from": "a@b.c", "warnDays": 14, "password": "x"}},
	} {
		if s := admin.expect(403, req.m, req.p, req.body); !strings.HasPrefix(s, "otp_required") {
			t.Fatalf("%s %s: %s", req.m, req.p, s)
		}
	}
	// ... but not the everyday ones
	admin.expect(200, "PUT", "/api/settings", map[string]any{"email": "a@b.c", "keyType": "rsa2048", "renewDays": 30, "checkHours": 12})
	admin.expect(200, "POST", "/api/users", map[string]string{"username": "vic", "role": "viewer", "password": "vicpassword"})
	if !strings.HasPrefix(admin.expect(403, "POST", "/api/users", map[string]string{"username": "eve", "role": "admin", "password": "evepassword"}), "otp_required") {
		t.Fatal("expected otp_required")
	}
	// OTP_FRESH_MINUTES=0: a confirmed code counts for exactly one action
	admin.expect(400, "POST", "/api/me/2fa/verify", map[string]string{"code": "000000"})
	admin.expect(200, "POST", "/api/me/2fa/verify", map[string]string{"code": en.Recovery[1]})
	admin.expect(200, "POST", "/api/users", map[string]string{"username": "eve", "role": "admin", "password": "evepassword"})
	if !strings.HasPrefix(admin.expect(403, "POST", "/api/users", map[string]string{"username": "eve2", "role": "admin", "password": "evepassword"}), "otp_required") {
		t.Fatal("a confirmed code must only count once when the fresh window is 0")
	}
	a.otpFresh = time.Minute

	// recovery codes can be replaced (fresh code needed, which we have)
	var rc struct{ Recovery []string }
	_ = json.Unmarshal([]byte(admin.expect(200, "POST", "/api/me/2fa/recovery", map[string]string{})), &rc)
	if len(rc.Recovery) != 10 || rc.Recovery[0] == en.Recovery[2] {
		t.Fatal("new recovery codes")
	}
	newClient(t, srv).expect(200, "POST", "/api/login", map[string]string{"username": "boss", "password": "supersecret"}) // (old codes are gone)

	// viewers: 2FA optional, can be turned off again
	vic := newClient(t, srv)
	vic.expect(200, "POST", "/api/login", map[string]string{"username": "vic", "password": "vicpassword"})
	vic.expect(200, "GET", "/api/state", nil)
	if !logged(a, `user "vic" signed in from 127.0.0.1 (password only, no 2FA)`) {
		t.Fatal("password-only sign-in not logged")
	}
	vs := vic.turnOn2FA()
	vic.expect(200, "POST", "/api/me/2fa/disable", map[string]string{"code": nextCode(vs)})
	// admins can't turn it off
	admin.expect(400, "POST", "/api/me/2fa/disable", map[string]string{"code": rc.Recovery[0]})

	// "require 2FA for everyone": viewers must set it up too
	admin.expect(200, "PUT", "/api/settings", map[string]any{"email": "a@b.c", "keyType": "rsa2048", "renewDays": 30, "checkHours": 12, "require2faAll": true})
	if s := vic.expect(403, "GET", "/api/state", nil); !strings.HasPrefix(s, "mfa_setup_required") {
		t.Fatal(s)
	}
	vs = vic.turnOn2FA()
	vic.expect(200, "GET", "/api/state", nil)
	vic.expect(400, "POST", "/api/me/2fa/disable", map[string]string{"code": nextCode(vs)}) // now required

	// admin resets a user's 2FA (lost phone); not their own
	var users []userView
	_ = json.Unmarshal([]byte(admin.expect(200, "GET", "/api/users", nil)), &users)
	ids := map[string]string{}
	for _, u := range users {
		ids[u.Username] = u.ID
		if u.Username == "vic" && !u.TOTP {
			t.Fatal("vic should have 2FA on")
		}
	}
	admin.expect(400, "POST", "/api/users/"+ids["boss"]+"/reset-2fa", map[string]string{})
	admin.expect(200, "POST", "/api/users/"+ids["vic"]+"/reset-2fa", map[string]string{})
	vic.expect(401, "GET", "/api/state", nil) // signed out everywhere
	vic.expect(200, "POST", "/api/login", map[string]string{"username": "vic", "password": "vicpassword"})
	vic.expect(403, "GET", "/api/state", nil) // must set it up again
	if s := vic.expect(200, "GET", "/api/session", nil); !strings.Contains(s, `"mfaSetupRequired":true`) {
		t.Fatal(s)
	}

	// brute force on the code is throttled like logins
	bf := newClient(t, srv)
	bf.expect(200, "POST", "/api/login", map[string]string{"username": "boss", "password": "supersecret"})
	for i := 0; i < 4; i++ {
		bf.expect(401, "POST", "/api/login/otp", map[string]string{"code": "111111"})
	}
	bf.expect(401, "POST", "/api/login/otp", map[string]string{"code": "111111"})
	bf.expect(429, "POST", "/api/login/otp", map[string]string{"code": "111111"})
}

func TestDataLockAndCLIReset(t *testing.T) {
	dir := t.TempDir()
	st, _ := OpenStore(dir)
	sl, _ := loadSealer(dir)
	_ = st.Update(func(c *Config) error {
		c.Users = []*User{{ID: "1", Username: "boss", Role: RoleAdmin, TOTPSecret: sl.seal("X"), Recovery: []string{"h"}}}
		return nil
	})
	if err := lockDataDir(dir); err != nil {
		t.Fatal(err)
	}
	held := dataLock
	if err := lockDataDir(dir); err == nil {
		t.Fatal("second lock on the same data directory must fail (server running)")
	}
	held.Close() // "server stopped"
	if resetUser2FA(dir, "nobody") == 0 {
		t.Fatal("unknown user should fail")
	}
	if resetUser2FA(dir, "boss") != 0 {
		t.Fatal("reset failed")
	}
	st2, _ := OpenStore(dir)
	if u := st2.Snapshot().Users[0]; u.has2FA() || len(u.Recovery) != 0 {
		t.Fatalf("2FA not reset: %+v", u)
	}
}

func TestStoredSecretsEncrypted(t *testing.T) {
	// a config from an older version, with plain-text secrets
	dir := t.TempDir()
	os.WriteFile(dir+"/config.json", []byte(`{"settings":{"cfToken":"cf-plain-token"},"mail":{"password":"smtp-plain-pw","warnDays":14}}`), 0o600)
	st, _ := OpenStore(dir)
	sl, _ := loadSealer(dir)
	if n, err := st.SealSecrets(sl); err != nil || n != 2 {
		t.Fatalf("converted %d, err %v", n, err)
	}
	if n, _ := st.SealSecrets(sl); n != 0 {
		t.Fatal("already encrypted values must not be converted again")
	}
	raw, _ := os.ReadFile(dir + "/config.json")
	if strings.Contains(string(raw), "cf-plain-token") || strings.Contains(string(raw), "smtp-plain-pw") {
		t.Fatal("secrets still in plain text on disk")
	}
	c := st.Snapshot()
	if v, _ := sl.reveal(c.Settings.CFToken); v != "cf-plain-token" {
		t.Fatal("token does not decrypt back")
	}

	// the SMTP password is only decrypted for the moment of sending
	m := NewManager(st, dir)
	m.sealer = sl
	var got string
	m.mailer = func(ms MailSettings, _ []string, _, _ string) error { got = ms.Password; return nil }
	if err := m.send(c.Mail, []string{"a@example.org"}, "s", "b"); err != nil || got != "smtp-plain-pw" {
		t.Fatalf("send got %q, %v", got, err)
	}

	// new values entered in the UI are stored encrypted
	a, srv := newTestApp(t)
	admin := newClient(t, srv)
	admin.expect(200, "POST", "/api/setup", map[string]string{"code": a.setupCode, "username": "boss", "password": "supersecret"})
	admin.turnOn2FA() // also makes the session fresh for the token change
	fakeCloudflare(t)
	admin.expect(200, "POST", "/api/dns-accounts", map[string]any{"name": "main", "token": "tok-a"})
	admin.expect(200, "PUT", "/api/mail", map[string]any{"host": "smtp.example.org", "port": 587, "security": "starttls", "user": "u", "password": "new-smtp-pw", "from": "a@example.org", "warnDays": 14})
	raw, _ = os.ReadFile(a.dataDir + "/config.json")
	if strings.Contains(string(raw), `"tok-a"`) || strings.Contains(string(raw), "new-smtp-pw") {
		t.Fatal("new secrets written in plain text")
	}
	c = a.store.Snapshot()
	if v, _ := a.mgr.sealer.reveal(c.DNS[0].Token); v != "tok-a" || !isSealed(c.Mail.Password) {
		t.Fatal("new secrets not encrypted correctly")
	}
	if s := admin.expect(200, "GET", "/api/state", nil); strings.Contains(s, `"tok-a"`) || strings.Contains(s, "v1:") {
		t.Fatal("secret (or its ciphertext) sent to the browser")
	}

	// successful sign-ins are logged with how they happened
	admin.expect(200, "POST", "/api/logout", nil)
	admin.expect(200, "POST", "/api/login", map[string]string{"username": "boss", "password": "supersecret"})
	var logs []string
	for _, l := range a.mgr.Logs() {
		logs = append(logs, l.Msg)
	}
	all := strings.Join(logs, "\n")
	if strings.Contains(all, "signed in from") {
		t.Fatal("logged as signed in before the 2FA code")
	}
	_ = all
}

func logged(a *app, line string) bool {
	for _, l := range a.mgr.Logs() {
		if l.Msg == line {
			return true
		}
	}
	return false
}
