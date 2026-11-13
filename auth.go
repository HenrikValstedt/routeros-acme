package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"

	cookieName = "rosacme_session"
	sessionTTL = 7 * 24 * time.Hour
)

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,32}$`)

func validRole(r string) bool { return r == RoleAdmin || r == RoleViewer }

func checkPassword(pw string) error {
	if len(pw) < 8 || len(pw) > 72 {
		return errors.New("password must be 8-72 characters")
	}
	return nil
}

func hashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---- sessions (in memory; users log in again after a container restart) ----

type session struct {
	userID  string
	expires time.Time
	mfaWait bool      // password accepted, waiting for the 2FA code
	fails   int       // wrong 2FA codes in this login attempt
	fresh   time.Time // when a 2FA code was last entered (for sensitive actions)
	oneShot bool      // the code was entered for one specific action (the "Confirm it's you" prompt)
}

const mfaWaitTTL = 5 * time.Minute

type sessionStore struct {
	mu sync.Mutex
	m  map[string]session
}

func (s *sessionStore) create(userID string, mfaWait bool, fresh time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.m {
		if now.After(v.expires) {
			delete(s.m, k)
		}
	}
	ttl := sessionTTL
	if mfaWait {
		ttl = mfaWaitTTL
	}
	t := randToken(32)
	s.m[t] = session{userID: userID, expires: now.Add(ttl), mfaWait: mfaWait, fresh: fresh}
	return t
}

func (s *sessionStore) get(token string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[token]
	if !ok || time.Now().After(v.expires) {
		delete(s.m, token)
		return session{}, false
	}
	return v, true
}

// update changes a live session; fn returning false deletes it.
func (s *sessionStore) update(token string, fn func(*session) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.m[token]; ok {
		if fn(&v) {
			s.m[token] = v
		} else {
			delete(s.m, token)
		}
	}
}

func (s *sessionStore) remove(token string) {
	s.mu.Lock()
	delete(s.m, token)
	s.mu.Unlock()
}

// removeUser ends all sessions of a user except keepToken.
func (s *sessionStore) removeUser(userID, keepToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if v.userID == userID && k != keepToken {
			delete(s.m, k)
		}
	}
}

// ---- login throttling ----
// Per client IP: 5 failures => that address is locked for 5 minutes.
// Per account:  10 failures, from any addresses => password sign-in to that account is
// locked for 15 minutes (passkey sign-in still works, so an attacker can't lock out an
// admin who has a passkey). Unknown usernames are counted the same way.

type throttle struct {
	mu    sync.Mutex
	limit int
	lock  time.Duration
	m     map[string]*struct {
		fails int
		until time.Time
	}
}

func newThrottle() *throttle { return newThrottleN(5, 5*time.Minute) }

func newThrottleN(limit int, lock time.Duration) *throttle {
	return &throttle{limit: limit, lock: lock, m: map[string]*struct {
		fails int
		until time.Time
	}{}}
}

func accountKey(username string) string {
	return "user:" + strings.ToLower(strings.TrimSpace(username))
}

func (t *throttle) blocked(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[ip]
	return e != nil && time.Now().Before(e.until)
}

func (t *throttle) fail(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[ip]
	if e == nil {
		e = &struct {
			fails int
			until time.Time
		}{}
		t.m[ip] = e
	}
	if e.fails++; e.fails >= t.limit {
		e.fails, e.until = 0, time.Now().Add(t.lock)
	}
}

func (t *throttle) ok(ip string) {
	t.mu.Lock()
	delete(t.m, ip)
	t.mu.Unlock()
}

// ---- bootstrap ----

// initUsers migrates the legacy single password, creates an admin from
// ADMIN_USER/ADMIN_PASSWORD if there are no users, or otherwise prints a one-time
// setup code that the first-run page asks for.
func (a *app) initUsers() error {
	return a.store.Update(func(c *Config) error {
		if len(c.Users) == 0 && c.Settings.AdminHash != "" {
			c.Users = append(c.Users, &User{ID: newID(), Username: "admin", Role: RoleAdmin, Hash: c.Settings.AdminHash, Created: time.Now()})
			log.Printf("migrated legacy web password to user %q (role admin)", "admin")
		}
		c.Settings.AdminHash = ""
		if len(c.Users) > 0 {
			if os.Getenv("ADMIN_PASSWORD") != "" {
				log.Printf("note: ADMIN_PASSWORD is ignored because users already exist")
			}
			return nil
		}
		if pw := os.Getenv("ADMIN_PASSWORD"); pw != "" {
			name := env("ADMIN_USER", "admin")
			if !usernameRE.MatchString(name) {
				return errors.New("ADMIN_USER: invalid username")
			}
			if err := checkPassword(pw); err != nil {
				return errors.New("ADMIN_PASSWORD: " + err.Error())
			}
			h, err := hashPassword(pw)
			if err != nil {
				return err
			}
			c.Users = append(c.Users, &User{ID: newID(), Username: name, Role: RoleAdmin, Hash: h, Created: time.Now()})
			log.Printf("created admin user %q from environment", name)
			return nil
		}
		a.setupCode = randToken(9)
		log.Printf("==> FIRST RUN: open the web UI and create the admin account. Setup code: %s", a.setupCode)
		return nil
	})
}

// ---- request authentication ----

type ctxUserKey struct{}

func currentUser(r *http.Request) *User {
	u, _ := r.Context().Value(ctxUserKey{}).(*User)
	return u
}

func sessionToken(r *http.Request) string {
	if c, err := r.Cookie(cookieName); err == nil {
		return c.Value
	}
	return ""
}

// sessionUser returns a copy of the logged-in user, or nil.
// A session still waiting for its 2FA code is not logged in.
func (a *app) sessionUser(r *http.Request) *User {
	s, ok := a.sessions.get(sessionToken(r))
	if !ok || s.mfaWait {
		return nil
	}
	id := s.userID
	var u *User
	a.store.Read(func(c *Config) {
		if x := c.user(id); x != nil {
			cp := *x
			u = &cp
		}
	})
	return u
}

// need wraps a handler: role "" = any logged-in user, RoleAdmin = admins only.
// A user who must use 2FA but hasn't set it up yet is refused (see needAny).
func (a *app) need(role string, h http.HandlerFunc) http.HandlerFunc { return a.guard(role, false, h) }

// needAny allows any logged-in user, also one who still has to set up 2FA
// (for the 2FA setup itself, the session and logout).
func (a *app) needAny(h http.HandlerFunc) http.HandlerFunc { return a.guard("", true, h) }

func (a *app) mustSetup2FA(u *User) bool {
	var req bool
	a.store.Read(func(c *Config) { req = u.needs2FA(*c) })
	return req && !u.has2FA()
}

func (a *app) guard(role string, setupOK bool, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := a.sessionUser(r)
		if u == nil {
			fail(w, http.StatusUnauthorized, errors.New("login required"))
			return
		}
		if !setupOK && a.mustSetup2FA(u) {
			fail(w, http.StatusForbidden, errors.New("mfa_setup_required: set up two-factor authentication first"))
			return
		}
		if role == RoleAdmin && u.Role != RoleAdmin {
			fail(w, http.StatusForbidden, errors.New("admin role required"))
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxUserKey{}, u)))
	}
}

func (a *app) setCookie(w http.ResponseWriter, r *http.Request, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: a.basePath + "/", MaxAge: maxAge,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: a.cookieSecure || a.proxy.isHTTPS(r),
	})
}

type userView struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	Email        string    `json:"email"`
	Notify       bool      `json:"notify"`
	Created      time.Time `json:"created"`
	LastLogin    time.Time `json:"lastLogin,omitzero"`
	TOTP         bool      `json:"totp"`         // 2FA is on
	RecoveryLeft int       `json:"recoveryLeft"` // unused recovery codes
	Passkeys     int       `json:"passkeys"`     // number of passkeys
}

func viewOf(u *User) userView {
	return userView{u.ID, u.Username, u.Role, u.Email, u.Notify, u.Created, u.LastLogin, u.has2FA(), len(u.Recovery), len(u.Passkeys)}
}

// ---- handlers ----

func (a *app) getSession(w http.ResponseWriter, r *http.Request) {
	var setup bool
	a.store.Read(func(c *Config) { setup = len(c.Users) == 0 })
	resp := map[string]any{"setupRequired": setup, "user": nil, "resetEnabled": a.resetEnabled(),
		"mfaPending": false, "mfaSetupRequired": false, "passkey": a.passkeyStatus(r)}
	if s, ok := a.sessions.get(sessionToken(r)); ok && s.mfaWait {
		resp["mfaPending"] = true
	}
	if u := a.sessionUser(r); u != nil {
		resp["user"] = viewOf(u)
		resp["mfaSetupRequired"] = a.mustSetup2FA(u)
	}
	writeJSON(w, resp)
}

type credentials struct {
	Code     string `json:"code"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *app) postSetup(w http.ResponseWriter, r *http.Request) {
	ip := a.proxy.clientIP(r)
	if a.throttle.blocked(ip) {
		fail(w, http.StatusTooManyRequests, errors.New("too many attempts, try again in a few minutes"))
		return
	}
	var in credentials
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, err)
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if !usernameRE.MatchString(in.Username) {
		fail(w, 400, errors.New("username: 1-32 characters of letters, digits . _ @ -"))
		return
	}
	if err := checkPassword(in.Password); err != nil {
		fail(w, 400, err)
		return
	}
	email, err := parseEmail(in.Email)
	if err != nil {
		fail(w, 400, err)
		return
	}
	h, err := hashPassword(in.Password)
	if err != nil {
		fail(w, 500, err)
		return
	}
	u := &User{ID: newID(), Username: in.Username, Role: RoleAdmin, Hash: h, Email: email, Notify: email != "",
		Created: time.Now(), LastLogin: time.Now()}
	err = a.store.Update(func(c *Config) error {
		if len(c.Users) > 0 {
			return errors.New("setup has already been completed")
		}
		if a.setupCode == "" || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(in.Code)), []byte(a.setupCode)) != 1 {
			return errors.New("wrong setup code (see the container log)")
		}
		c.Users = append(c.Users, u)
		a.setupCode = "" // guarded by the store lock
		return nil
	})
	if err != nil {
		a.throttle.fail(ip)
		fail(w, 400, err)
		return
	}
	a.mgr.logf("setup: admin user %q created from %s", u.Username, ip)
	a.setCookie(w, r, a.sessions.create(u.ID, false, time.Time{}), int(sessionTTL.Seconds()))
	writeJSON(w, viewOf(u))
}

// dummyHash keeps login timing the same for unknown usernames.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)

func (a *app) postLogin(w http.ResponseWriter, r *http.Request) {
	ip := a.proxy.clientIP(r)
	if a.throttle.blocked(ip) {
		fail(w, http.StatusTooManyRequests, errors.New("too many failed logins, try again in a few minutes"))
		return
	}
	var in credentials
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, err)
		return
	}
	if a.acctThrottle.blocked(accountKey(in.Username)) {
		a.mgr.logf("login for %q from %s refused: too many failed attempts for this account", in.Username, ip)
		fail(w, http.StatusTooManyRequests, errors.New("too many failed sign-ins for this account, try again in 15 minutes (signing in with a passkey still works)"))
		return
	}
	var id, hash string
	var twoFA bool
	a.store.Read(func(c *Config) {
		if u := c.userByName(strings.TrimSpace(in.Username)); u != nil {
			id, hash, twoFA = u.ID, u.Hash, u.has2FA()
		}
	})
	if id == "" {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(in.Password))
	}
	if id == "" || bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) != nil {
		a.throttle.fail(ip)
		a.acctThrottle.fail(accountKey(in.Username))
		a.mgr.logf("login failed for %q from %s", in.Username, ip)
		fail(w, http.StatusUnauthorized, errors.New("wrong username or password"))
		return
	}
	a.throttle.ok(ip)
	if twoFA {
		// password is right; the session only becomes a login after the 2FA code (postLoginOTP)
		a.setCookie(w, r, a.sessions.create(id, true, time.Time{}), int(mfaWaitTTL.Seconds()))
		writeJSON(w, map[string]bool{"mfa": true})
		return
	}
	a.setCookie(w, r, a.sessions.create(id, false, time.Time{}), int(sessionTTL.Seconds()))
	v := a.touchLogin(id)
	a.mgr.logf("user %q signed in from %s (password only, no 2FA)", v.Username, ip)
	writeJSON(w, v)
}

func (a *app) postLogout(w http.ResponseWriter, r *http.Request) {
	a.sessions.remove(sessionToken(r))
	a.setCookie(w, r, "", -1)
	writeJSON(w, "ok")
}

func (a *app) putMyPassword(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(me.Hash), []byte(in.Current)) != nil {
		fail(w, 400, errors.New("current password is wrong"))
		return
	}
	if err := checkPassword(in.New); err != nil {
		fail(w, 400, err)
		return
	}
	h, err := hashPassword(in.New)
	if err == nil {
		err = a.store.Update(func(c *Config) error {
			if x := c.user(me.ID); x != nil {
				x.Hash = h
			}
			return nil
		})
	}
	if err != nil {
		fail(w, 500, err)
		return
	}
	a.sessions.removeUser(me.ID, sessionToken(r)) // log out other devices
	writeJSON(w, "ok")
}

func (a *app) listUsers(w http.ResponseWriter, _ *http.Request) {
	out := []userView{}
	a.store.Read(func(c *Config) {
		for _, u := range c.Users {
			out = append(out, viewOf(u))
		}
	})
	writeJSON(w, out)
}

func (a *app) saveUser(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	var in struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Notify   bool   `json:"notify"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, err)
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	// creating or promoting an admin, or changing an existing user's password
	// (an account takeover), needs a fresh 2FA code
	var wasAdmin bool
	a.store.Read(func(c *Config) {
		if x := c.user(in.ID); x != nil {
			wasAdmin = x.Role == RoleAdmin
		}
	})
	if ((in.ID != "" && in.Password != "") || (in.Role == RoleAdmin && !wasAdmin)) && !a.requireFresh(w, r) {
		return
	}
	email, err := parseEmail(in.Email)
	if err != nil {
		fail(w, 400, err)
		return
	}
	if email == "" {
		in.Notify = false
	}
	switch {
	case !usernameRE.MatchString(in.Username):
		fail(w, 400, errors.New("username: 1-32 characters of letters, digits . _ @ -"))
		return
	case !validRole(in.Role):
		fail(w, 400, errors.New("role must be admin or viewer"))
		return
	case in.ID == "" && in.Password == "":
		fail(w, 400, errors.New("password is required for a new user"))
		return
	}
	var hash string
	if in.Password != "" {
		if err := checkPassword(in.Password); err != nil {
			fail(w, 400, err)
			return
		}
		var err error
		if hash, err = hashPassword(in.Password); err != nil {
			fail(w, 500, err)
			return
		}
	}
	err = a.store.Update(func(c *Config) error {
		if o := c.userByName(in.Username); o != nil && o.ID != in.ID {
			return errors.New("username already exists")
		}
		if in.ID == "" {
			c.Users = append(c.Users, &User{ID: newID(), Username: in.Username, Role: in.Role, Hash: hash,
				Email: email, Notify: in.Notify, Created: time.Now()})
			return nil
		}
		x := c.user(in.ID)
		if x == nil {
			return errors.New("not found")
		}
		if x.Role == RoleAdmin && in.Role != RoleAdmin && c.adminCount() == 1 {
			return errors.New("cannot remove the admin role from the last admin")
		}
		x.Username, x.Role, x.Email, x.Notify = in.Username, in.Role, email, in.Notify
		if hash != "" {
			x.Hash = hash
		}
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	if in.ID != "" && hash != "" {
		keep := ""
		if in.ID == me.ID {
			keep = sessionToken(r)
		}
		a.sessions.removeUser(in.ID, keep)
	}
	a.mgr.logf("user %q saved by %s (role %s)", in.Username, me.Username, in.Role)
	writeJSON(w, "ok")
}

func (a *app) deleteUser(w http.ResponseWriter, r *http.Request) {
	me, id := currentUser(r), r.PathValue("id")
	var name string
	err := a.store.Update(func(c *Config) error {
		x := c.user(id)
		switch {
		case x == nil:
			return errors.New("not found")
		case x.ID == me.ID:
			return errors.New("you cannot delete your own account")
		case x.Role == RoleAdmin && c.adminCount() == 1:
			return errors.New("cannot delete the last admin")
		}
		name = x.Username
		c.Users = deleteByID(c.Users, id)
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.sessions.removeUser(id, "")
	a.mgr.logf("user %q deleted by %s", name, me.Username)
	writeJSON(w, "ok")
}

func deleteByID(us []*User, id string) []*User {
	out := us[:0]
	for _, u := range us {
		if u.ID != id {
			out = append(out, u)
		}
	}
	return out
}
