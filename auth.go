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
}

type sessionStore struct {
	mu sync.Mutex
	m  map[string]session
}

func (s *sessionStore) create(userID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.m {
		if now.After(v.expires) {
			delete(s.m, k)
		}
	}
	t := randToken(32)
	s.m[t] = session{userID, now.Add(sessionTTL)}
	return t
}

func (s *sessionStore) get(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[token]
	if !ok || time.Now().After(v.expires) {
		delete(s.m, token)
		return "", false
	}
	return v.userID, true
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

// ---- login throttling: 5 failures per client IP => locked for 5 minutes ----

type throttle struct {
	mu sync.Mutex
	m  map[string]*struct {
		fails int
		until time.Time
	}
}

func newThrottle() *throttle {
	return &throttle{m: map[string]*struct {
		fails int
		until time.Time
	}{}}
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
	if e.fails++; e.fails >= 5 {
		e.fails, e.until = 0, time.Now().Add(5*time.Minute)
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
func (a *app) sessionUser(r *http.Request) *User {
	id, ok := a.sessions.get(sessionToken(r))
	if !ok {
		return nil
	}
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
func (a *app) need(role string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := a.sessionUser(r)
		if u == nil {
			fail(w, http.StatusUnauthorized, errors.New("login required"))
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
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	Email     string    `json:"email"`
	Notify    bool      `json:"notify"`
	Created   time.Time `json:"created"`
	LastLogin time.Time `json:"lastLogin,omitzero"`
}

func viewOf(u *User) userView {
	return userView{u.ID, u.Username, u.Role, u.Email, u.Notify, u.Created, u.LastLogin}
}

// ---- handlers ----

func (a *app) getSession(w http.ResponseWriter, r *http.Request) {
	var setup bool
	a.store.Read(func(c *Config) { setup = len(c.Users) == 0 })
	resp := map[string]any{"setupRequired": setup, "user": nil, "resetEnabled": a.resetEnabled()}
	if u := a.sessionUser(r); u != nil {
		resp["user"] = viewOf(u)
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
	a.setCookie(w, r, a.sessions.create(u.ID), int(sessionTTL.Seconds()))
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
	var id, hash string
	a.store.Read(func(c *Config) {
		if u := c.userByName(strings.TrimSpace(in.Username)); u != nil {
			id, hash = u.ID, u.Hash
		}
	})
	if id == "" {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(in.Password))
	}
	if id == "" || bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) != nil {
		a.throttle.fail(ip)
		a.mgr.logf("login failed for %q from %s", in.Username, ip)
		fail(w, http.StatusUnauthorized, errors.New("wrong username or password"))
		return
	}
	a.throttle.ok(ip)
	var u userView
	_ = a.store.Update(func(c *Config) error {
		if x := c.user(id); x != nil {
			x.LastLogin = time.Now()
			u = viewOf(x)
		}
		return nil
	})
	a.setCookie(w, r, a.sessions.create(id), int(sessionTTL.Seconds()))
	writeJSON(w, u)
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
