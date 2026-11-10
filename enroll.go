package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	inviteTTL = 72 * time.Hour
	resetTTL  = time.Hour
)

func tokenHash(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// findToken returns the live token of the given kind (caller holds the store lock).
func findToken(c *Config, kind, raw string) *Token {
	if raw == "" {
		return nil
	}
	c.pruneTokens()
	h := tokenHash(raw)
	for _, t := range c.Tokens {
		if t.Kind == kind && t.Hash == h {
			return t
		}
	}
	return nil
}

func removeToken(c *Config, id string) {
	out := c.Tokens[:0]
	for _, t := range c.Tokens {
		if t.ID != id {
			out = append(out, t)
		}
	}
	c.Tokens = out
}

func normalizePublicURL(s string) (string, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	if s == "" {
		return "", nil
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("public URL must look like https://certs.example.com or https://example.com/certs")
	}
	return s, nil
}

// linkBase is where e-mailed links point. The configured public URL wins. For admin
// requests (invites) it can fall back to the URL the admin is using right now. It is
// never derived from an anonymous request (that would allow Host-header poisoning).
func (a *app) linkBase(r *http.Request, fromAdmin bool) string {
	var pub string
	a.store.Read(func(c *Config) { pub = c.Mail.PublicURL })
	if pub != "" || !fromAdmin {
		return pub
	}
	scheme := "http"
	if a.proxy.isHTTPS(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host + a.basePath
}

// ---- mail settings ----

type mailView struct {
	MailSettings
	HasPassword bool `json:"hasPassword"`
}

func mailViewOf(m MailSettings) mailView {
	v := mailView{MailSettings: m, HasPassword: m.Password != ""}
	v.Password = ""
	return v
}

// validateMail checks and normalises SMTP settings. full also checks the fields that only
// matter when saving (public URL, recipients, warning days).
func validateMail(in *MailSettings, full bool) error {
	in.Host, in.User = strings.TrimSpace(in.Host), strings.TrimSpace(in.User)
	var err error
	if in.From, err = parseEmail(in.From); err != nil {
		return fmt.Errorf("from: %w", err)
	}
	switch {
	case in.Host != "" && in.From == "":
		return errors.New("from address is required")
	case in.Port < 1 || in.Port > 65535:
		return errors.New("invalid port")
	case in.Security != "starttls" && in.Security != "tls" && in.Security != "none":
		return errors.New("security must be starttls, tls or none")
	}
	if !full {
		return nil
	}
	if in.PublicURL, err = normalizePublicURL(in.PublicURL); err != nil {
		return err
	}
	for _, x := range splitList(in.ExtraRecipients) {
		if _, err := parseEmail(x); err != nil {
			return err
		}
	}
	if in.WarnDays < 1 || in.WarnDays > 60 {
		return errors.New("warning days must be 1-60")
	}
	return nil
}

func (a *app) putMail(w http.ResponseWriter, r *http.Request) {
	var in MailSettings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, err)
		return
	}
	if in.Password != "" && !a.requireFresh(w, r) {
		return
	}
	if err := validateMail(&in, true); err != nil {
		fail(w, 400, err)
		return
	}
	err := a.store.Update(func(c *Config) error {
		pw := c.Mail.Password
		if in.Password != "" {
			pw = a.mgr.sealer.seal(in.Password) // stored encrypted
		}
		if in.User == "" {
			pw = ""
		}
		in.Password = pw
		c.Mail = in
		return nil
	})
	if err != nil {
		fail(w, 500, err)
		return
	}
	a.mgr.logf("e-mail settings changed by %s", currentUser(r).Username)
	writeJSON(w, "ok")
}

func (a *app) testMail(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	var in struct {
		To       string        `json:"to"`
		Settings *MailSettings `json:"settings"` // what's in the form, saved or not; nothing is stored
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	to, err := parseEmail(in.To)
	if err == nil && to == "" {
		to = me.Email
	}
	if err != nil || to == "" {
		fail(w, 400, errors.New("enter a recipient (or set an e-mail address on your account)"))
		return
	}
	saved := a.store.Snapshot().Mail
	ms := saved
	if in.Settings != nil {
		ms = *in.Settings
		if err := validateMail(&ms, false); err != nil {
			fail(w, 400, err)
			return
		}
		if !ms.configured() {
			fail(w, 400, errors.New("fill in the SMTP server and from address"))
			return
		}
		switch {
		case ms.Password != "":
			ms.Password = a.mgr.sealer.seal(ms.Password) // typed in the form: used for this test only
		case ms.User != "" && ms.User == saved.User && ms.Host == saved.Host && ms.Port == saved.Port:
			ms.Password = saved.Password // unchanged server and user: reuse the saved password
		default:
			ms.Password = "" // never send the saved password to a different server or user
		}
	}
	body := fmt.Sprintf("This is a test message from RouterOS ACME, sent by %s.\n\nIf you can read this, e-mail delivery works.\n", me.Username)
	if err := a.mgr.send(ms, []string{to}, "[RouterOS ACME] Test e-mail", body); err != nil {
		a.mgr.logf("test e-mail to %s failed: %v", to, err)
		fail(w, 400, err)
		return
	}
	a.mgr.logf("test e-mail sent to %s by %s", to, me.Username)
	writeJSON(w, "sent to "+to)
}

// ---- my account ----

func (a *app) putMe(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	var in struct {
		Email  string `json:"email"`
		Notify bool   `json:"notify"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, err)
		return
	}
	email, err := parseEmail(in.Email)
	if err != nil {
		fail(w, 400, err)
		return
	}
	if in.Notify && email == "" {
		fail(w, 400, errors.New("an e-mail address is required for notifications"))
		return
	}
	_ = a.store.Update(func(c *Config) error {
		if x := c.user(me.ID); x != nil {
			x.Email, x.Notify = email, in.Notify
		}
		return nil
	})
	writeJSON(w, "ok")
}

// ---- invitations ----

type inviteView struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedBy string    `json:"createdBy"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
}

func (a *app) listInvites(w http.ResponseWriter, _ *http.Request) {
	out := []inviteView{}
	_ = a.store.Update(func(c *Config) error {
		c.pruneTokens()
		for _, t := range c.Tokens {
			if t.Kind == "invite" {
				out = append(out, inviteView{t.ID, t.Email, t.Role, t.CreatedBy, t.Created, t.Expires})
			}
		}
		return nil
	})
	writeJSON(w, out)
}

func (a *app) createInvite(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	var in struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, err)
		return
	}
	email, err := parseEmail(in.Email)
	if err != nil || email == "" {
		fail(w, 400, errors.New("a valid e-mail address is required"))
		return
	}
	if !validRole(in.Role) {
		fail(w, 400, errors.New("role must be admin or viewer"))
		return
	}
	if in.Role == RoleAdmin && !a.requireFresh(w, r) {
		return
	}
	raw := randToken(24)
	var ms MailSettings
	err = a.store.Update(func(c *Config) error {
		for _, u := range c.Users {
			if strings.EqualFold(u.Email, email) {
				return fmt.Errorf("user %q already has this e-mail address", u.Username)
			}
		}
		// replace an older pending invite for the same address
		out := c.Tokens[:0]
		for _, t := range c.Tokens {
			if !(t.Kind == "invite" && strings.EqualFold(t.Email, email)) {
				out = append(out, t)
			}
		}
		c.Tokens = append(out, &Token{ID: newID(), Kind: "invite", Hash: tokenHash(raw), Email: email, Role: in.Role,
			CreatedBy: me.Username, Created: time.Now(), Expires: time.Now().Add(inviteTTL)})
		ms = c.Mail
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	link := a.linkBase(r, true) + "/#invite=" + raw
	resp := map[string]any{"link": link, "emailed": false}
	if ms.configured() {
		body := fmt.Sprintf("Hello,\n\n%s has invited you to RouterOS ACME with the role %q.\n\n"+
			"Open this link to choose your username and password (valid for %d hours):\n\n%s\n\n"+
			"If you didn't expect this invitation you can ignore this e-mail.\n", me.Username, in.Role, int(inviteTTL.Hours()), link)
		if err := a.mgr.send(ms, []string{email}, "[RouterOS ACME] You have been invited", body); err != nil {
			resp["error"] = err.Error()
			a.mgr.logf("invite e-mail to %s failed: %v", email, err)
		} else {
			resp["emailed"] = true
		}
	}
	a.mgr.logf("invitation for %s (%s) created by %s", email, in.Role, me.Username)
	writeJSON(w, resp)
}

func (a *app) deleteInvite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_ = a.store.Update(func(c *Config) error { removeToken(c, id); return nil })
	writeJSON(w, "ok")
}

// public: look up an invitation so the page can show who is being invited.
func (a *app) checkInvite(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	var t *Token
	_ = a.store.Update(func(c *Config) error {
		if x := findToken(c, "invite", in.Token); x != nil {
			cp := *x
			t = &cp
		}
		return nil
	})
	if t == nil {
		fail(w, 404, errors.New("this invitation link is invalid or has expired"))
		return
	}
	writeJSON(w, map[string]string{"email": t.Email, "role": t.Role})
}

func (a *app) acceptInvite(w http.ResponseWriter, r *http.Request) {
	ip := a.proxy.clientIP(r)
	if a.throttle.blocked(ip) {
		fail(w, http.StatusTooManyRequests, errors.New("too many attempts, try again in a few minutes"))
		return
	}
	var in struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
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
	h, err := hashPassword(in.Password)
	if err != nil {
		fail(w, 500, err)
		return
	}
	var u *User
	err = a.store.Update(func(c *Config) error {
		t := findToken(c, "invite", in.Token)
		if t == nil {
			a.throttle.fail(ip)
			return errors.New("this invitation link is invalid or has expired")
		}
		if c.userByName(in.Username) != nil {
			return errors.New("username already exists, choose another")
		}
		u = &User{ID: newID(), Username: in.Username, Role: t.Role, Hash: h, Email: t.Email,
			Notify: t.Role == RoleAdmin, Created: time.Now(), LastLogin: time.Now()}
		c.Users = append(c.Users, u)
		removeToken(c, t.ID)
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.mgr.logf("user %q (%s, %s) joined via invitation from %s", u.Username, u.Email, u.Role, ip)
	a.setCookie(w, r, a.sessions.create(u.ID, false, time.Time{}), int(sessionTTL.Seconds()))
	writeJSON(w, viewOf(u))
}

// ---- password reset ----

func (a *app) resetEnabled() bool {
	var ok bool
	a.store.Read(func(c *Config) { ok = c.Mail.configured() && c.Mail.PublicURL != "" })
	return ok
}

// public. Always answers the same way so it can't be used to discover accounts.
func (a *app) forgotPassword(w http.ResponseWriter, r *http.Request) {
	ip := a.proxy.clientIP(r)
	if a.mailThrottle.blocked(ip) {
		fail(w, http.StatusTooManyRequests, errors.New("too many requests, try again in a few minutes"))
		return
	}
	a.mailThrottle.fail(ip) // every request counts: max 5 per 5 minutes per client
	var in struct {
		Login string `json:"login"` // username or e-mail
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	login := strings.TrimSpace(in.Login)
	const answer = "If an account with an e-mail address matches, a reset link has been sent."
	if login == "" || !a.resetEnabled() {
		writeJSON(w, answer)
		return
	}
	raw := randToken(24)
	var user User
	var ms MailSettings
	_ = a.store.Update(func(c *Config) error {
		var u *User
		for _, x := range c.Users {
			if x.Email != "" && (strings.EqualFold(x.Username, login) || strings.EqualFold(x.Email, login)) {
				u = x
				break
			}
		}
		if u == nil {
			return nil
		}
		out := c.Tokens[:0]
		for _, t := range c.Tokens {
			if !(t.Kind == "reset" && t.UserID == u.ID) {
				out = append(out, t)
			}
		}
		c.Tokens = append(out, &Token{ID: newID(), Kind: "reset", Hash: tokenHash(raw), Email: u.Email, UserID: u.ID,
			Created: time.Now(), Expires: time.Now().Add(resetTTL)})
		user, ms = *u, c.Mail
		return nil
	})
	if user.ID != "" {
		link := ms.PublicURL + "/#reset=" + raw
		go func() { // async: response time must not reveal whether the account exists
			body := fmt.Sprintf("Hello %s,\n\nA password reset was requested for your RouterOS ACME account (from %s).\n\n"+
				"Open this link to choose a new password (valid for %d minutes):\n\n%s\n\n"+
				"If you didn't request this, you can ignore this e-mail. Your password stays unchanged.\n",
				user.Username, ip, int(resetTTL.Minutes()), link)
			if err := a.mgr.send(ms, []string{user.Email}, "[RouterOS ACME] Password reset", body); err != nil {
				a.mgr.logf("password reset e-mail for %q failed: %v", user.Username, err)
				return
			}
			a.mgr.logf("password reset link sent to %q (requested from %s)", user.Username, ip)
		}()
	}
	writeJSON(w, answer)
}

func (a *app) resetPassword(w http.ResponseWriter, r *http.Request) {
	ip := a.proxy.clientIP(r)
	if a.throttle.blocked(ip) {
		fail(w, http.StatusTooManyRequests, errors.New("too many attempts, try again in a few minutes"))
		return
	}
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, err)
		return
	}
	if err := checkPassword(in.Password); err != nil {
		fail(w, 400, err)
		return
	}
	h, err := hashPassword(in.Password)
	if err != nil {
		fail(w, 500, err)
		return
	}
	var uid, name string
	err = a.store.Update(func(c *Config) error {
		t := findToken(c, "reset", in.Token)
		if t == nil {
			a.throttle.fail(ip)
			return errors.New("this reset link is invalid or has expired")
		}
		removeToken(c, t.ID)
		u := c.user(t.UserID)
		if u == nil {
			return errors.New("account no longer exists")
		}
		u.Hash, uid, name = h, u.ID, u.Username
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.sessions.removeUser(uid, "")
	a.mgr.logf("password for %q reset via e-mail link from %s", name, ip)
	writeJSON(w, map[string]string{"username": name})
}
