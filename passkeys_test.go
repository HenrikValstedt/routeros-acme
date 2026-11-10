package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestRelyingPartyRules(t *testing.T) {
	a := &app{}
	a.proxy, _ = parseTrustedProxies("10.0.0.1")
	for _, c := range []struct {
		host, peer, proto string
		ok                bool
		rpid, why         string
	}{
		{"localhost:8080", "127.0.0.1:1", "", true, "localhost", ""},             // http://localhost is allowed by browsers
		{"192.168.1.10:8080", "127.0.0.1:1", "", false, "", "not an IP address"}, // IPs never
		{"certs.example.com", "127.0.0.1:1", "", false, "", "HTTPS"},             // plain http
		{"certs.example.com", "10.0.0.1:1", "https", true, "certs.example.com", ""},
		{"Certs.Example.com:443", "10.0.0.1:1", "https", true, "certs.example.com", ""},
		{"certs.example.com", "203.0.113.5:1", "https", false, "", "HTTPS"}, // X-Forwarded-Proto from an untrusted client
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host, r.RemoteAddr = c.host, c.peer
		if c.proto != "" {
			r.Header.Set("X-Forwarded-Proto", c.proto)
		}
		_, rpid, err := a.relyingParty(r)
		if c.ok != (err == nil) || rpid != c.rpid || (err != nil && !strings.Contains(err.Error(), c.why)) {
			t.Errorf("%s via %s: rpid=%q err=%v", c.host, c.peer, rpid, err)
		}
	}
}

func TestPasskeyEndpointsGuarded(t *testing.T) {
	a, srv := newTestApp(t)
	admin := newClient(t, srv) // httptest server: Host is 127.0.0.1 -> passkeys unavailable
	admin.expect(200, "POST", "/api/setup", map[string]string{"code": a.setupCode, "username": "boss", "password": "supersecret"})
	if s := admin.expect(200, "GET", "/api/session", nil); !strings.Contains(s, `"available":false`) || !strings.Contains(s, "IP address") {
		t.Fatal(s)
	}
	// before 2FA: nothing (not even passkeys)
	admin.expect(403, "POST", "/api/me/passkeys/begin", map[string]string{"name": "x"})
	admin.turnOn2FA()
	// on an IP address passkeys are refused with an explanation
	if s := admin.expect(400, "POST", "/api/me/passkeys/begin", map[string]string{"name": "x"}); !strings.Contains(s, "IP address") {
		t.Fatal(s)
	}
	if s := newClient(t, srv).expect(400, "POST", "/api/passkey/login/begin", nil); !strings.Contains(s, "IP address") {
		t.Fatal(s)
	}
	// adding a passkey is a sensitive action
	a.otpFresh = 0
	if s := admin.expect(403, "POST", "/api/me/passkeys/begin", map[string]string{"name": "x"}); !strings.HasPrefix(s, "otp_required") {
		t.Fatal(s)
	}
	admin.expect(403, "DELETE", "/api/me/passkeys/nope", nil)
	// finishing without a valid ceremony fails cleanly
	newClient(t, srv).expect(400, "POST", "/api/passkey/login/finish?c=bogus", map[string]string{})
}

func TestCeremoniesSingleUse(t *testing.T) {
	cs := &ceremonyStore{m: map[string]ceremony{}}
	id := cs.put(ceremony{kind: "login"})
	if _, ok := cs.take(id, "register"); ok {
		t.Fatal("wrong kind accepted")
	}
	id = cs.put(ceremony{kind: "login"})
	if _, ok := cs.take(id, "login"); !ok {
		t.Fatal("valid ceremony refused")
	}
	if _, ok := cs.take(id, "login"); ok {
		t.Fatal("a ceremony must only be finished once")
	}
	id = cs.put(ceremony{kind: "login"})
	cs.m[id] = ceremony{kind: "login", expires: time.Now().Add(-time.Second)}
	if _, ok := cs.take(id, "login"); ok {
		t.Fatal("expired ceremony accepted")
	}
}

func TestResetsRemovePasskeys(t *testing.T) {
	dir := t.TempDir()
	st, _ := OpenStore(dir)
	sl, _ := loadSealer(dir)
	_ = st.Update(func(c *Config) error {
		c.Users = []*User{{ID: "1", Username: "boss", Role: RoleAdmin, TOTPSecret: sl.seal("X"),
			Passkeys: []*Passkey{{ID: "p1", Name: "phone", RPID: "certs.example.com", Cred: webauthn.Credential{ID: []byte("c")}}}}}
		return nil
	})
	if resetUser2FA(dir, "boss") != 0 {
		t.Fatal("reset failed")
	}
	st2, _ := OpenStore(dir)
	if len(st2.Snapshot().Users[0].Passkeys) != 0 {
		t.Fatal("command-line reset must remove passkeys")
	}
	u := &User{Passkeys: []*Passkey{{ID: "p"}}}
	clearPasskeys(u)
	if u.Passkeys != nil {
		t.Fatal("clearPasskeys")
	}
	// passkeys are filtered by site name
	w := waUser{&User{Passkeys: []*Passkey{{RPID: "a.example"}, {RPID: "b.example"}}}, "a.example"}
	if len(w.WebAuthnCredentials()) != 1 {
		t.Fatal("credentials of another site name must not be offered")
	}
}
