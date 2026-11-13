package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Passkeys (WebAuthn) are an optional, faster way to sign in and to confirm sensitive
// actions. They add to TOTP and never replace it: a passkey can only be added while TOTP
// is on, and the code stays the fallback (e.g. on plain http:// or another device).
// A passkey is bound to the site name (RP ID) it was created on, e.g. certs.example.com.

// Passkey is one registered credential of a user.
type Passkey struct {
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	RPID     string              `json:"rpId"`
	Cred     webauthn.Credential `json:"credential"`
	Created  time.Time           `json:"created"`
	LastUsed time.Time           `json:"lastUsed,omitzero"`
}

// waUser adapts a User to the WebAuthn library, with only the passkeys of one site name.
type waUser struct {
	u    *User
	rpID string
}

func (w waUser) WebAuthnID() []byte          { return w.u.WebAuthnID }
func (w waUser) WebAuthnName() string        { return w.u.Username }
func (w waUser) WebAuthnDisplayName() string { return w.u.Username }
func (w waUser) WebAuthnCredentials() []webauthn.Credential {
	var out []webauthn.Credential
	for _, p := range w.u.Passkeys {
		if p.RPID == w.rpID {
			out = append(out, p.Cred)
		}
	}
	return out
}

// relyingParty describes this site for WebAuthn, from the address the browser used.
// Browsers only allow passkeys on https:// (or http://localhost) with a host name.
func (a *app) relyingParty(r *http.Request) (*webauthn.WebAuthn, string, error) {
	host := r.Host
	hostname := host
	if h, port, err := net.SplitHostPort(host); err == nil {
		hostname = h
		if port == "443" {
			host = h // browsers leave the default port out of the origin
		}
	}
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	https := a.proxy.isHTTPS(r)
	switch {
	case net.ParseIP(hostname) != nil:
		return nil, "", errors.New("passkeys need a host name such as certs.example.com, not an IP address")
	case !https && hostname != "localhost":
		if hint := a.proxy.proxyHint(r); hint != "" {
			return nil, "", errors.New("passkeys need HTTPS. " + hint)
		}
		return nil, "", errors.New("passkeys need HTTPS – open RouterOS ACME through its https:// address (see Running behind a reverse proxy)")
	}
	scheme := "https"
	if !https {
		scheme = "http" // localhost only
	}
	// With a Public URL set (Settings → E-mail), passkeys belong to that address only,
	// whatever Host header a request carries.
	var pub string
	if a.store != nil {
		a.store.Read(func(c *Config) { pub = c.Mail.PublicURL })
	}
	if pub != "" {
		u, err := url.Parse(pub)
		if err == nil && u.Host != "" {
			want := strings.TrimSuffix(strings.ToLower(u.Host), ":443")
			if want != strings.ToLower(host) || u.Scheme != scheme {
				return nil, "", fmt.Errorf("passkeys work at %s (the Public URL under Settings → E-mail) – open RouterOS ACME there", strings.TrimRight(pub, "/"))
			}
		}
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID: hostname, RPDisplayName: "RouterOS ACME", RPOrigins: []string{scheme + "://" + host},
	})
	if err != nil {
		return nil, "", fmt.Errorf("passkeys: %w", err)
	}
	return wa, hostname, nil
}

// ---- short-lived ceremony state (between the browser's two calls) ----

type ceremony struct {
	kind    string // "login" | "register" | "confirm"
	userID  string
	rpID    string
	name    string
	session webauthn.SessionData
	expires time.Time
}

type ceremonyStore struct {
	mu sync.Mutex
	m  map[string]ceremony
}

func (s *ceremonyStore) put(c ceremony) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.m {
		if now.After(v.expires) {
			delete(s.m, k)
		}
	}
	c.expires = now.Add(5 * time.Minute)
	id := randToken(18)
	s.m[id] = c
	return id
}

// take returns and removes a ceremony (each can be finished once).
func (s *ceremonyStore) take(id, kind string) (ceremony, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.m[id]
	delete(s.m, id)
	return c, ok && c.kind == kind && time.Now().Before(c.expires)
}

// ---- helpers ----

func (a *app) passkeyStatus(r *http.Request) map[string]any {
	_, rpID, err := a.relyingParty(r)
	if err != nil {
		return map[string]any{"available": false, "reason": err.Error()}
	}
	return map[string]any{"available": true, "rpId": rpID}
}

func passkeyViews(u *User) []map[string]any {
	out := []map[string]any{}
	for _, p := range u.Passkeys {
		out = append(out, map[string]any{"id": p.ID, "name": p.Name, "rpId": p.RPID, "created": p.Created, "lastUsed": p.LastUsed})
	}
	return out
}

// usePasskey records a successful use (sign counter, flags, last used).
func (a *app) usePasskey(userID string, cred *webauthn.Credential) string {
	var name string
	_ = a.store.Update(func(c *Config) error {
		if u := c.user(userID); u != nil {
			for _, p := range u.Passkeys {
				if string(p.Cred.ID) == string(cred.ID) {
					p.Cred.Authenticator = cred.Authenticator
					p.Cred.Flags = cred.Flags
					p.LastUsed, name = time.Now(), p.Name
				}
			}
		}
		return nil
	})
	return name
}

func clearPasskeys(u *User) { u.Passkeys = nil }

// ---- sign in with a passkey (replaces password and code) ----

func (a *app) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if a.throttle.blocked(a.proxy.clientIP(r)) {
		fail(w, http.StatusTooManyRequests, errors.New("too many failed attempts, try again in a few minutes"))
		return
	}
	wa, rpID, err := a.relyingParty(r)
	if err != nil {
		fail(w, 400, err)
		return
	}
	opts, sd, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		fail(w, 500, err)
		return
	}
	id := a.ceremonies.put(ceremony{kind: "login", rpID: rpID, session: *sd})
	writeJSON(w, map[string]any{"ceremony": id, "options": opts})
}

func (a *app) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	ip := a.proxy.clientIP(r)
	if a.throttle.blocked(ip) {
		fail(w, http.StatusTooManyRequests, errors.New("too many failed attempts, try again in a few minutes"))
		return
	}
	cer, ok := a.ceremonies.take(r.URL.Query().Get("c"), "login")
	wa, rpID, err := a.relyingParty(r)
	if !ok || err != nil || rpID != cer.rpID {
		fail(w, 400, errors.New("the passkey sign-in expired – try again"))
		return
	}
	var userID string
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		var found *User
		a.store.Read(func(c *Config) {
			for _, u := range c.Users {
				if len(u.WebAuthnID) > 0 && string(u.WebAuthnID) == string(userHandle) {
					cp := *u
					found = &cp
				}
			}
		})
		if found == nil {
			return nil, errors.New("unknown passkey")
		}
		userID = found.ID
		return waUser{found, rpID}, nil
	}
	_, cred, err := wa.FinishPasskeyLogin(handler, cer.session, r)
	if err != nil {
		a.throttle.fail(ip)
		a.mgr.logf("passkey sign-in failed from %s: %v", ip, err)
		fail(w, http.StatusUnauthorized, errors.New("that passkey wasn't accepted – use your password and code instead"))
		return
	}
	a.throttle.ok(ip)
	name := a.usePasskey(userID, cred)
	a.setCookie(w, r, a.sessions.create(userID, false, time.Now()), int(sessionTTL.Seconds()))
	v := a.touchLogin(userID)
	a.mgr.logf("user %q signed in from %s with passkey %q", v.Username, ip, name)
	writeJSON(w, map[string]any{"user": v})
}

// ---- managing my passkeys ----

func (a *app) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	if !me.has2FA() {
		fail(w, 400, errors.New("turn on two-factor authentication with a code first – it stays the fallback for your passkeys"))
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		in.Name = "Passkey"
	}
	if len(in.Name) > 40 {
		fail(w, 400, errors.New("name is too long"))
		return
	}
	wa, rpID, err := a.relyingParty(r)
	if err != nil {
		fail(w, 400, err)
		return
	}
	// a stable, random user handle (never the username)
	_ = a.store.Update(func(c *Config) error {
		if u := c.user(me.ID); u != nil && len(u.WebAuthnID) == 0 {
			id := make([]byte, 32)
			_, _ = rand.Read(id)
			u.WebAuthnID = id
		}
		return nil
	})
	var u User
	a.store.Read(func(c *Config) { u = *c.user(me.ID) })
	wu := waUser{&u, rpID}
	var exclude []protocol.CredentialDescriptor
	for _, c := range wu.WebAuthnCredentials() {
		exclude = append(exclude, c.Descriptor())
	}
	opts, sd, err := wa.BeginRegistration(wu,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExclusions(exclude))
	if err != nil {
		fail(w, 500, err)
		return
	}
	id := a.ceremonies.put(ceremony{kind: "register", userID: me.ID, rpID: rpID, name: in.Name, session: *sd})
	writeJSON(w, map[string]any{"ceremony": id, "options": opts})
}

func (a *app) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	cer, ok := a.ceremonies.take(r.URL.Query().Get("c"), "register")
	wa, rpID, err := a.relyingParty(r)
	if !ok || err != nil || cer.userID != me.ID || rpID != cer.rpID {
		fail(w, 400, errors.New("adding the passkey expired – try again"))
		return
	}
	var u User
	a.store.Read(func(c *Config) { u = *c.user(me.ID) })
	cred, err := wa.FinishRegistration(waUser{&u, rpID}, cer.session, r)
	if err != nil {
		fail(w, 400, fmt.Errorf("the passkey couldn't be added: %v", err))
		return
	}
	p := &Passkey{ID: newID(), Name: cer.name, RPID: rpID, Cred: *cred, Created: time.Now()}
	_ = a.store.Update(func(c *Config) error {
		if x := c.user(me.ID); x != nil {
			x.Passkeys = append(x.Passkeys, p)
		}
		return nil
	})
	a.mgr.logf("user %q added passkey %q for %s", me.Username, p.Name, rpID)
	writeJSON(w, map[string]string{"id": p.ID, "name": p.Name})
}

func (a *app) passkeyDelete(w http.ResponseWriter, r *http.Request) {
	me, id := currentUser(r), r.PathValue("id")
	var name string
	_ = a.store.Update(func(c *Config) error {
		if x := c.user(me.ID); x != nil {
			x.Passkeys = slices.DeleteFunc(x.Passkeys, func(p *Passkey) bool {
				if p.ID == id {
					name = p.Name
					return true
				}
				return false
			})
		}
		return nil
	})
	if name == "" {
		fail(w, 404, errors.New("not found"))
		return
	}
	a.mgr.logf("user %q removed passkey %q", me.Username, name)
	writeJSON(w, "ok")
}

// ---- "Confirm it's you" with a passkey ----

func (a *app) passkeyConfirmBegin(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	wa, rpID, err := a.relyingParty(r)
	if err != nil {
		fail(w, 400, err)
		return
	}
	wu := waUser{me, rpID}
	if len(wu.WebAuthnCredentials()) == 0 {
		fail(w, 400, errors.New("you have no passkey for this address – use a code"))
		return
	}
	opts, sd, err := wa.BeginLogin(wu, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		fail(w, 500, err)
		return
	}
	id := a.ceremonies.put(ceremony{kind: "confirm", userID: me.ID, rpID: rpID, session: *sd})
	writeJSON(w, map[string]any{"ceremony": id, "options": opts})
}

func (a *app) passkeyConfirmFinish(w http.ResponseWriter, r *http.Request) {
	me, ip := currentUser(r), a.proxy.clientIP(r)
	cer, ok := a.ceremonies.take(r.URL.Query().Get("c"), "confirm")
	wa, rpID, err := a.relyingParty(r)
	if !ok || err != nil || cer.userID != me.ID || rpID != cer.rpID {
		fail(w, 400, errors.New("the confirmation expired – try again"))
		return
	}
	var u User
	a.store.Read(func(c *Config) { u = *c.user(me.ID) })
	cred, err := wa.FinishLogin(waUser{&u, rpID}, cer.session, r)
	if err != nil {
		a.throttle.fail(ip)
		fail(w, 400, errors.New("that passkey wasn't accepted – try again or use a code"))
		return
	}
	a.usePasskey(me.ID, cred)
	a.sessions.update(sessionToken(r), func(s *session) bool { s.fresh, s.oneShot = time.Now(), true; return true })
	writeJSON(w, "ok")
}
