package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"
)

// ---- verification ----

// verifyCode checks a TOTP code or a recovery code for the user and consumes it
// (a TOTP step can't be reused; a recovery code is deleted).
func (a *app) verifyCode(userID, code string) (ok, usedRecovery bool) {
	_ = a.store.Update(func(c *Config) error {
		u := c.user(userID)
		if u == nil || !u.has2FA() {
			return nil
		}
		if looksLikeRecovery(code) {
			h := hashRecovery(code)
			if i := slices.Index(u.Recovery, h); i >= 0 {
				u.Recovery = slices.Delete(u.Recovery, i, i+1)
				ok, usedRecovery = true, true
			}
			return nil
		}
		secret, err := a.mgr.sealer.open(u.TOTPSecret)
		if err != nil {
			return nil
		}
		if step, good := checkTOTP(secret, code, u.TOTPLastStep, time.Now()); good {
			u.TOTPLastStep, ok = step, true
		}
		return nil
	})
	return ok, usedRecovery
}

func (a *app) touchLogin(id string) userView {
	var v userView
	_ = a.store.Update(func(c *Config) error {
		if x := c.user(id); x != nil {
			x.LastLogin = time.Now()
			v = viewOf(x)
		}
		return nil
	})
	return v
}

type codeInput struct {
	Code string `json:"code"`
}

// postLoginOTP finishes a login: password was accepted, now the 2FA code.
func (a *app) postLoginOTP(w http.ResponseWriter, r *http.Request) {
	ip := a.proxy.clientIP(r)
	if a.throttle.blocked(ip) {
		fail(w, http.StatusTooManyRequests, errors.New("too many failed attempts, try again in a few minutes"))
		return
	}
	tok := sessionToken(r)
	s, ok := a.sessions.get(tok)
	if !ok || !s.mfaWait {
		fail(w, http.StatusUnauthorized, errors.New("sign in with your password first"))
		return
	}
	var in codeInput
	_ = json.NewDecoder(r.Body).Decode(&in)
	good, recovery := a.verifyCode(s.userID, in.Code)
	if !good {
		a.throttle.fail(ip)
		a.sessions.update(tok, func(x *session) bool { x.fails++; return x.fails < 5 })
		name := s.userID
		a.store.Read(func(c *Config) {
			if u := c.user(s.userID); u != nil {
				name = u.Username
			}
		})
		a.mgr.logf("2FA code rejected for %q from %s", name, ip)
		fail(w, http.StatusUnauthorized, errors.New("wrong or expired code"))
		return
	}
	a.throttle.ok(ip)
	a.sessions.remove(tok)
	a.setCookie(w, r, a.sessions.create(s.userID, false, time.Now()), int(sessionTTL.Seconds()))
	v := a.touchLogin(s.userID)
	if recovery {
		a.mgr.logf("user %q signed in from %s with password + recovery code (%d left)", v.Username, ip, v.RecoveryLeft)
	} else {
		a.mgr.logf("user %q signed in from %s with password + 2FA code", v.Username, ip)
	}
	writeJSON(w, map[string]any{"user": v, "usedRecovery": recovery})
}

// ---- fresh code for sensitive actions ----

// isFresh: a code was entered within the fresh window (OTP_FRESH_MINUTES), or one was just
// entered in the "Confirm it's you" prompt for this very action. That one counts once, so
// OTP_FRESH_MINUTES=0 means "ask every time".
func (a *app) isFresh(r *http.Request) bool {
	tok := sessionToken(r)
	s, ok := a.sessions.get(tok)
	if !ok || s.mfaWait {
		return false
	}
	if time.Since(s.fresh) < a.otpFresh {
		return true
	}
	if s.oneShot && time.Since(s.fresh) < time.Minute {
		a.sessions.update(tok, func(x *session) bool { x.oneShot = false; return true })
		return true
	}
	return false
}

// requireFresh answers 403 "otp_required" unless a 2FA code was entered recently.
// The web UI then asks for a code (POST /api/me/2fa/verify) and repeats the request.
func (a *app) requireFresh(w http.ResponseWriter, r *http.Request) bool {
	if a.isFresh(r) {
		return true
	}
	fail(w, http.StatusForbidden, errors.New("otp_required: confirm with a code from your authenticator app"))
	return false
}

func (a *app) stepUp(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.requireFresh(w, r) {
			h(w, r)
		}
	}
}

func (a *app) verify2FA(w http.ResponseWriter, r *http.Request) {
	me, ip := currentUser(r), a.proxy.clientIP(r)
	if a.throttle.blocked(ip) {
		fail(w, http.StatusTooManyRequests, errors.New("too many failed attempts, try again in a few minutes"))
		return
	}
	var in codeInput
	_ = json.NewDecoder(r.Body).Decode(&in)
	if ok, _ := a.verifyCode(me.ID, in.Code); !ok {
		a.throttle.fail(ip)
		fail(w, http.StatusBadRequest, errors.New("wrong or expired code")) // 400, not 401: still signed in
		return
	}
	a.throttle.ok(ip)
	a.sessions.update(sessionToken(r), func(s *session) bool { s.fresh, s.oneShot = time.Now(), true; return true })
	writeJSON(w, "ok")
}

// ---- setting up / managing 2FA ----

// setup2FA starts (or restarts) setup: a new secret, kept pending until a code confirms it.
func (a *app) setup2FA(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	if me.has2FA() {
		fail(w, 400, errors.New("two-factor authentication is already on"))
		return
	}
	secret := newTOTPSecret()
	err := a.store.Update(func(c *Config) error {
		if x := c.user(me.ID); x != nil {
			x.TOTPPending = a.mgr.sealer.seal(secret)
		}
		return nil
	})
	if err != nil {
		fail(w, 500, err)
		return
	}
	uri := otpauthURI(secret, me.Username, "RouterOS ACME")
	svg, err := qrSVG(uri)
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, map[string]string{"secret": secret, "uri": uri, "qr": svg})
}

// enable2FA confirms the pending secret with a code and returns the recovery codes (shown once).
func (a *app) enable2FA(w http.ResponseWriter, r *http.Request) {
	me, ip := currentUser(r), a.proxy.clientIP(r)
	if a.throttle.blocked(ip) {
		fail(w, http.StatusTooManyRequests, errors.New("too many failed attempts, try again in a few minutes"))
		return
	}
	var in codeInput
	_ = json.NewDecoder(r.Body).Decode(&in)
	plain, hashed := newRecoveryCodes()
	err := a.store.Update(func(c *Config) error {
		x := c.user(me.ID)
		if x == nil || x.TOTPPending == "" {
			return errors.New("start the setup again")
		}
		secret, err := a.mgr.sealer.open(x.TOTPPending)
		if err != nil {
			return err
		}
		step, ok := checkTOTP(secret, in.Code, 0, time.Now())
		if !ok {
			a.throttle.fail(ip)
			return errors.New("that code doesn't match – check the time on your phone and try the next code")
		}
		x.TOTPSecret, x.TOTPPending, x.TOTPLastStep, x.Recovery = x.TOTPPending, "", step, hashed
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.sessions.update(sessionToken(r), func(s *session) bool { s.fresh = time.Now(); return true })
	a.sessions.removeUser(me.ID, sessionToken(r)) // other sessions predate 2FA
	a.mgr.logf("user %q turned on two-factor authentication", me.Username)
	writeJSON(w, map[string]any{"recovery": plain})
}

// newRecovery replaces all recovery codes (needs a fresh code).
func (a *app) newRecovery(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	plain, hashed := newRecoveryCodes()
	_ = a.store.Update(func(c *Config) error {
		if x := c.user(me.ID); x != nil && x.has2FA() {
			x.Recovery = hashed
		}
		return nil
	})
	a.mgr.logf("user %q created new recovery codes", me.Username)
	writeJSON(w, map[string]any{"recovery": plain})
}

// disable2FA turns 2FA off for users who aren't required to have it.
func (a *app) disable2FA(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	var in codeInput
	_ = json.NewDecoder(r.Body).Decode(&in)
	var required bool
	a.store.Read(func(c *Config) { required = me.needs2FA(*c) })
	if required {
		fail(w, 400, errors.New("two-factor authentication is required for your account"))
		return
	}
	if ok, _ := a.verifyCode(me.ID, in.Code); !ok {
		fail(w, http.StatusBadRequest, errors.New("wrong or expired code"))
		return
	}
	_ = a.store.Update(func(c *Config) error {
		if x := c.user(me.ID); x != nil {
			x.TOTPSecret, x.TOTPPending, x.TOTPLastStep, x.Recovery = "", "", 0, nil
			clearPasskeys(x) // passkeys build on 2FA
		}
		return nil
	})
	a.mgr.logf("user %q turned off two-factor authentication (and removed passkeys)", me.Username)
	writeJSON(w, "ok")
}

// reset2FA lets an admin clear another user's 2FA (lost phone). The user sets it up
// again at the next sign-in when it is required for them.
func (a *app) reset2FA(w http.ResponseWriter, r *http.Request) {
	me, id := currentUser(r), r.PathValue("id")
	if id == me.ID {
		fail(w, 400, errors.New("use My account to change your own two-factor authentication"))
		return
	}
	var name string
	err := a.store.Update(func(c *Config) error {
		x := c.user(id)
		if x == nil {
			return errors.New("not found")
		}
		x.TOTPSecret, x.TOTPPending, x.TOTPLastStep, x.Recovery, name = "", "", 0, nil, x.Username
		clearPasskeys(x)
		return nil
	})
	if err != nil {
		fail(w, 404, err)
		return
	}
	a.sessions.removeUser(id, "")
	a.mgr.logf("two-factor authentication and passkeys of %q reset by %s", name, me.Username)
	writeJSON(w, "ok")
}
